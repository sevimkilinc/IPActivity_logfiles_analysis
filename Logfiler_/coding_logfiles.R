#install.packages("mapdata")
library(stringr)
library(ggplot2)
library(maps)
library(ggrepel)
library(leaflet)
library("dplyr")
library("lubridate")
library("httr")
library("rjson")


#############################
#### OLA3 OPGAVE 3 ##########
############################

setwd("~/Documents/GitHub/Logfiler_/log")
file.exists("~/Documents/GitHub/Logfiler_/log") # hvis din sti fucker
Logfiles <- list.files(pattern = "access*", path = ".")
log_content <- lapply(Logfiles, readLines)

først_log_df=as.data.frame(log_content[[1]])

# Kombiner indholdet af alle logfiler
all_logs <- do.call(c, log_content)

extract_log_data <- function(raw_log) {
  ip <- str_extract(raw_log, "^\\S+") # Første ord: IP-adresse
  status <- str_extract(raw_log, "\\s\\d{3}\\s") # HTTP-statuskode
  path <- str_extract(raw_log, "\\\"(GET|POST|HEAD)\\s(.*?)\\sHTTP") # Path fra forespørgsel
  time <- str_extract(raw_log, "\\[(.*?)\\]") # Tidsstempel
  user_agent <- str_extract(raw_log, "\\\"[^\"]*\\\"$") %>%
    str_remove_all("^\\\"|\\\"$")
  # Sikrer præcis 5 elementer i returneringen
  result <- c(ip, time, path, status, user_agent)
  length(result) <- 5 # Fylder med NA hvis nødvendigt
  return(result)
}


# Parse loglinjer og opret en data frame
parsed_logs <- t(sapply(all_logs, extract_log_data))
colnames(parsed_logs) <- c("IP", "Time", "Path", "Status", "Useragent")
logs_prep <- as.data.frame(parsed_logs, stringsAsFactors = FALSE)

logs_prep$Status <- as.numeric(logs_prep$Status)


# Fjern eventuelle rownames i logs_prep
rownames(logs_prep) <- NULL

# Ekstrahér dato fra Time-kolonnen
logs_prep$Date <- sub(":(.*)", "", logs_prep$Time) # Fjern tid fra datoen
logs_prep$Date <- gsub("\\[", "", logs_prep$Date) # Fjern venstre parentes
logs_prep$Date <- as.Date(logs_prep$Date, format = "%d/%b/%Y") # Konverter til Date-type

# Ekstrahér alene tid (hh:mm:ss) fra Time-kolonnen
logs_prep$Exacttime <- sub("^.*:(\\d{2}:\\d{2}:\\d{2}).*", "\\1", logs_prep$Time)

structured_logs <- logs_prep

structured_logs$Useragent[is.na(structured_logs$Useragent)] <- "Unknown"


#############################################
# Aktive IP-adresser og deres forekomster
#############################################

# Optælling af unikke IP-adresser pr. dato
active_ips_per_day <- aggregate(IP ~ Date, data = structured_logs, FUN = function(x) length(unique(x)))
colnames(active_ips_per_day) <- c("Date", "UniqueIPs")

# Optælling af forekomster for hver IP-adresse
IP_antal <- table(structured_logs$IP)
sorted_IP_antal <- sort(IP_antal, decreasing = TRUE)
Antal_forekomster_IP <- as.data.frame(sorted_IP_antal)
colnames(Antal_forekomster_IP) <- c("IP", "Antal")

# Visualisering af de mest aktive IP-adresser
Top_aktive_IPs <- head(Antal_forekomster_IP, 15)
ggplot(Top_aktive_IPs, aes(x = reorder(IP, -Antal), y = Antal, fill = IP)) +
  geom_bar(stat = "identity") +
  labs(title = "IP-adressen 192.0.102.40 udviser den højeste registrerede aktivitet",
       x = "IP-adresse",
       y = "Antal forekomster") +
  theme_minimal() +
  theme(axis.text.x = element_text(angle = 45, hjust = 1),
        plot.title = element_text(face = "bold"),
        legend.position = "none")


######################################################
## Mistænksomme HTTP-forespørgsler (statuscode 404) ##
######################################################

logs_404 <- structured_logs[structured_logs$Status == 404, ]
Path_404_summary <- aggregate(Status ~ Path + IP, data = logs_404, FUN = length)
colnames(Path_404_summary) <- c("Path", "IP", "Count404")

# Sortér stier efter antal fejl (mest til mindst)
sorted_path_404 <- Path_404_summary[order(-Path_404_summary$Count404), ]
rownames(sorted_path_404) <- NULL

Top_10_suspicious <- head(sorted_path_404, 10)
suspicious_ips <- unique(Top_10_suspicious$IP)

###########################################################
## Hent IP-data fra ipinfo.io og generer et Leaflet-kort ##
###########################################################

# Definer liste over de 10 mistænksomme IP'er
top_10_suspicious_IPs <- c(
  "93.162.98.150", "5.179.80.204", "83.97.73.87", 
  "170.64.220.120", "157.90.209.77", "159.100.22.187", 
  "162.240.239.98", "5.179.80.205"
)


fetch_ip_details <- function(ip) {
  response <- GET(paste0("https://ipinfo.io/", ip, "/json"))
  if (status_code(response) == 200) {
    data <- fromJSON(rawToChar(response$content))
    loc <- strsplit(data$loc, ",")[[1]]
    return(data.frame(
      IP = ip,
      City = data$city,
      Region = data$region,
      Country = data$country,
      Latitude = as.numeric(loc[1]),
      Longitude = as.numeric(loc[2]),
      stringsAsFactors = FALSE
    ))
  }
  return(NULL)
}

# Hent data for de  mistænksomme IP'er
top_suspicious_IP_details <- do.call(rbind, lapply(top_10_suspicious_IPs, fetch_ip_details))

# Fjern dubletter baseret på Latitude og Longitude
top_suspicious_IP_details <- top_suspicious_IP_details[!duplicated(top_suspicious_IP_details[, c("Latitude", "Longitude")]), ]

#####################################
## Opret Leaflet-kort med IP-data ##
#####################################

leaflet(data = top_suspicious_IP_details) %>%
  addProviderTiles("Esri.WorldImagery") %>%  # Esri kort med jordfarver
  addCircleMarkers(
    lng = ~Longitude, lat = ~Latitude,
    label = ~paste("IP:", IP),
    labelOptions = labelOptions(
      noHide = TRUE,
      direction = "top",
      textsize = "12px",
      style = list("color" = "black", "font-weight" = "bold")
    ),
    color = "red", radius = 6, fillOpacity = 0.8
  ) %>%
  setView(lng = 20, lat = 55, zoom = 4) %>%
  addControl(
    html = "<h3 style='color:blue; text-align:center;'>Globale hotspots for potentielt skadelig IP-aktivitet</h3>",
    position = "topright"
  )



################################################################
### ekstra observation: inddrages i mistænksomme request   #####
################################################################

# ud kolonnen statuskode, er det 200 observationer som er lig 12.289 af hele 15.000 observationer dvs. 81.9%
round(sum(structured_logs$Status == 200) / nrow(structured_logs) * 100, 1)

Top_1_active_IP <- "192.0.102.40" 

# Hent oplysninger for IP-adressen
response <- GET(paste0("https://ipinfo.io/", Top_1_active_IP, "/json"))
data <- fromJSON(rawToChar(response$content))
cat(paste("IP:", data$ip, "\nCITY:", data$city, "\nREGION:", 
          data$region, "\nCOUNTRY:", data$country, "\nLOCATION:", data$loc, "\n"))

###################################
# Geografisk placering af IP
###################################

# Ekstraher koordinater
coords <- strsplit(data$loc, ",")[[1]]
latitude <- as.numeric(coords[1])
longitude <- as.numeric(coords[2])

# Hent kortdata for USA
state_map <- map_data("state")

# Data for punktet (IP-adressen)
point_data <- data.frame(longitude = longitude, latitude = latitude)

# Tilføj fiktive værdier til gradientfyld (ens for hele kortet)
state_map$value <- runif(nrow(state_map), 1, 100)

# Visualiser IP-adressens placering med gradientfyld
ggplot() +
  geom_polygon(data = state_map, aes(x = long, y = lat, group = group, fill = value),
               color = "white", size = 0.2) +
  scale_fill_gradient(low = "lightblue", high = "darkblue") +  # Gradient uden forklaring
  geom_point(data = point_data, aes(x = longitude, y = latitude),
             color = "red", size = 3) +
  geom_label(data = point_data, aes(x = longitude, y = latitude, label = "192.0.102.40"),
             color = "white", size = 4, vjust = -1, fontface = "bold", fill = "black", label.size = 0) +
  coord_fixed(xlim = c(-130, -60), ylim = c(20, 55)) +  # Fokus på USA
  theme_minimal() +
  labs(
    title = "USA topper listen med den mest aktive IP-adresse:"
  ) +
  annotate("text", x = -125, y = 25, label = paste(
    "IP: 192.0.102.40\n",
    "CITY: Ashburn\n",
    "REGION: Virginia\n",
    "COUNTRY: US\n",
    "LOCATION: 39.0437,-77.4875"
  ),
  hjust = 0, color = "black", size = 4, fontface = "bold") +
  theme(
    legend.position = "none",  
    axis.title = element_blank(),
    axis.text = element_blank(),
    axis.ticks = element_blank(),
    plot.title = element_text(face = "bold", size = 14, hjust = 0.5)
  )


