import nmap
import time

def scan_ports(ip_address, ports):
  """
  Scan un ensemble de ports pour voir s'ils sont ouverts.

  Args:
    ip_address: L'adresse IP de la cible.
    ports: Une liste de numéros de port à scanner.

  Returns:
    Une liste de booléens indiquant si les ports sont ouverts ou fermés.
  """

  scanner = nmap.PortScanner()
  scanner.scan(ip_address, ports)

  results = []

  for port in ports:
    is_open = scanner[ip_address]['tcp'][port]['state'] == 'open'
    results.append(is_open)

  return results


def main():
  # Demander à l'utilisateur l'adresse IP et la liste de ports à scanner.
  ip_address = input("Adresse IP : ")
  ports = input("Numéros de port : ").split(",")

  # Scanner les ports.
  results = scan_ports(ip_address, ports)

  # Afficher les résultats.
  print("Ports ouverts :")
  for port, is_open in enumerate(results):
    if is_open:
      print("  {} ({})".format(port, ports[port]))

  # Détecter les ports filtrés.
  filtered_ports = []
  for port in ports:
    if scanner[ip_address]['tcp'][port]['state'] == 'filtered':
      filtered_ports.append(port)

  print("Ports filtrés :")
  for port in filtered_ports:
    print("  {}".format(port))

  # Détecter les ports avec un service connu.
  services = {}
  for port in ports:
    service = scanner[ip_address]['tcp'][port]['service']['name']
    services[port] = service

  print("Ports avec un service connu :")
  for port, service in services.items():
    print("  {} ({})".format(port, service))

  # Détecter les vulnérabilités.
  vulnerabilities = []
  for port in ports:
    if scanner[ip_address]['tcp'][port]['state'] == 'open':
      for script in scanner[ip_address]['tcp'][port]['scripts']:
        if script['id'] == 'Nmap Scripting Engine':
          if 'vulns' in script['output']:
            for vuln in script['output']['vulns']:
              vulnerabilities.append(vuln)

  print("Vulnérabilités :")
  for vuln in vulnerabilities:
    print(vuln)


if __name__ == "__main__":
  main()
