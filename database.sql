-- MySQL dump 10.13  Distrib 5.5.12, for solaris10 (i386)
--
-- Host: sql    Database: u_deltaquad_rights
-- ------------------------------------------------------
-- Server version	5.1.53

--
-- Table structure for table `accessnew`
--

DROP TABLE IF EXISTS `accessnew`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `accessnew` (
  `cloak` tinytext NOT NULL,
  `channel` text NOT NULL,
  `op` tinyint(1) NOT NULL,
  `voice` tinyint(1) NOT NULL,
  `ban` tinyint(1) NOT NULL,
  `kick` tinyint(1) NOT NULL,
  `globalmsg` tinyint(1) NOT NULL,
  `startup` tinyint(1) NOT NULL,
  `quiet` tinyint(1) NOT NULL,
  `nick` tinyint(1) NOT NULL,
  `mode` tinyint(1) NOT NULL,
  `trout` tinyint(1) NOT NULL,
  `permission` tinyint(1) NOT NULL,
  `restart` tinyint(1) NOT NULL,
  `joinpart` tinyint(1) NOT NULL,
  `blocked` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `channel`
--

DROP TABLE IF EXISTS `channel`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `channel` (
  `channel` tinytext NOT NULL,
  `join?` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;


--
-- Table structure for table `groups`
--

DROP TABLE IF EXISTS `groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `groups` (
  `group` tinytext NOT NULL,
  `flag` tinytext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rcblacklist`
--

DROP TABLE IF EXISTS `rcblacklist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `rcblacklist` (
  `stalk` tinytext NOT NULL,
  `channel` tinytext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `rcstalklist`
--

DROP TABLE IF EXISTS `rcstalklist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `rcstalklist` (
  `stalk` tinytext NOT NULL,
  `channel` tinytext NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;


