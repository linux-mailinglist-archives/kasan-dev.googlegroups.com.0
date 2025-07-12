Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB2UGZLBQMGQESRI2VHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 65A02B02BBD
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Jul 2025 17:47:04 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-879489ddf11sf559029839f.3
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Jul 2025 08:47:04 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1752335211; cv=pass;
        d=google.com; s=arc-20240605;
        b=h0rCk40kW922CXom58vlgCQjxoC3L2+OcrAaDBSYJMqiXxnSX/to3gLUQ+IS2CertU
         o2vGuhLymH8Cv37B/cqGP+YeevMLltwvO8iVXRI7CaECreWdJ9YwSpORnKZrmsYDXzq9
         XkhX2Ko+cz2KqWhXBeTiMa7C2pKuJibZmbNeBNaoyeKL9FvYVDcevU8GDZ2nYiWP+VBt
         juvcC5xGKGr4MuKNmCYOCANFSb8OyMFGmYXoXzehRMtEHZk0ZsSR/GkBhafBTN5AJFLs
         skG84rEqX+NXN6ly3ivxffb/lDyEBKdE8UltanoaHlsJpoWbRiOEb8PVYgw7D1Pehyv8
         lR3g==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:nodisclaimer
         :authentication-results-original:msip_labels:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=OdDeZMn0HU+KX2fPGwZfC/k+f9HnrwqPPsYIDUSGTjI=;
        fh=baVKmhZ6rVu3sFMgVv/6Yac6RDgPBm+TNsVrTkYWXes=;
        b=eXWneq58IqCuPo43mv6iAzdP4GpXXE0XUgY357SucXwdbzN5rCgQBZdfIeE7BOz/U7
         Z8J6o7f5+SWDJ6KbMrt00gnwO386T9hqb7rlNxClXs3ErL6+B/u9jJiwrGdWLIEVNJOZ
         0sP2iClauPp+7q05P4V+SWQFn6raeaIpElWhgJu5wg6XUgQG1NlHpZkQSVZ7DXqZ+KSz
         3CGrhHWKNRDUEacz9PoIqx+nRQFqVWq+SOU8l6LFgIAOO6CAcDGUuuD3KW0lFBIn46BX
         IQqyARDoAYzV1SR3MXpOwicHnqUS7tqXg+Nu3T5/LHCWoc1QdYn4RSsMI60Gl+AHt8Ah
         24jA==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=R6gQsQUe;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=R6gQsQUe;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752335211; x=1752940011; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding
         :nodisclaimer:authentication-results-original:msip_labels
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OdDeZMn0HU+KX2fPGwZfC/k+f9HnrwqPPsYIDUSGTjI=;
        b=NYhN9GXkPFbxofplDopzVWoFWjGj4laGsV8aNpM6T71Vq9CcNi33KlblJeltElMQLa
         Rn0ZzSeCEKjAOINX595jStyHv8/5ItBDhRauVxGywDayXBDNJvxodTYLQxAR5HKo1AqY
         2eg/TLv6NlA8pUjBrfCXDvrbh6+79gydr3aXl8Td9IpAIlMSP7y3a8hi18bFo7ohjGfA
         FxZ5EHNHzvnk0mBQMZPs0yEn0gywNPeIpZFHBqa32mqSs07kOUiN3AnOBcvbwuVOzF2j
         Fuqp0dFqMRWzl0Cw2hYqbq6m5YkSgpMpYpH3/9TXT1CljOzeBAp/5IO/8cSBwcQVCqZh
         4rmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752335211; x=1752940011;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:nodisclaimer
         :authentication-results-original:msip_labels:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OdDeZMn0HU+KX2fPGwZfC/k+f9HnrwqPPsYIDUSGTjI=;
        b=e9j0zFhVd5AHQK3ENNZK4jDzUFEXmqznr0FqWQoPRM15nx7Y3ERvHSGzSfHUdtfhGx
         NRBZI27xD4Uy6cVTm1IhEO9VgDXnKTC+HArrVG+z/SnpBMb33Wb7lMidmcdgalAZuRve
         0l1P6KRmyB9ZMLM4Tg3srXt6E1P8SeyDKhbrYFJfVtbzD0KWB35RGBhlkMnghYy5BSl6
         +DuUtvKcX0dc5J03KmRoUAO/E7HsRG+lPbOreW+l2Rx6xL81Rf43jK2zOmmLaHxaUPDU
         k322BWjgQ+1FXSQdl9dXRyFx9WxEzi5W/uTPIdEU/OE0LQeEEvbmg/dYkKiMISfVUWO2
         M77A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCXUBqldcLRT9YL14CdaK2eyb2nV8QSIoI0q4EpjsYLqeimjJXA9NQf3smUWNrN0pnk0z9S6aA==@lfdr.de
X-Gm-Message-State: AOJu0YziyHwtbEjdgXuhuJ/J89u3w0nWC3mOd7jsmzOxvhLZNax5IEQW
	uLWywKxH2ra13SXnFVx/b+I5xjDZ/9s9Ll6IeUpilmMqqXlLnHqJbXYO
X-Google-Smtp-Source: AGHT+IEe9wXybnQVaIVqOwVzsj5+063BlH86HN8f5/E2plM6fZ5V/cAFzRd1DHywCViBi1X2D0JnHw==
X-Received: by 2002:a05:6e02:188b:b0:3dd:d189:6511 with SMTP id e9e14a558f8ab-3e2556d42ddmr72563935ab.21.1752335210603;
        Sat, 12 Jul 2025 08:46:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfNuRW6DNoFiabCKuyNCVdQXMh8wjbVq5Z8xAnMJm72CQ==
Received: by 2002:a05:6e02:481b:b0:3de:143a:a012 with SMTP id
 e9e14a558f8ab-3e244036ba9ls26494795ab.0.-pod-prod-01-us; Sat, 12 Jul 2025
 08:46:49 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCWZsG3/ErvBZKqmwTOtp4GZYDKNWc+XLEy4V4WDFGXg9eexqWqlSwQXN375mqFeAvQEVjDOkJ89EtY=@googlegroups.com
X-Received: by 2002:a05:6e02:f:b0:3dc:79e5:e696 with SMTP id e9e14a558f8ab-3e255662968mr64011005ab.11.1752335209758;
        Sat, 12 Jul 2025 08:46:49 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1752335209; cv=pass;
        d=google.com; s=arc-20240605;
        b=ekorpbOeWnPPFP4XAEAr5wwxcdNopcyQFciozzJ0v23VvvbtFmp8bc0I2p7VeMFKs+
         isa9FEiPwMw9g2AMytXqyWjMsL/PxkHkaOy/gRpRjsUHD/2HEbfBxVSRVY0rroXUoMQz
         wKu520MCkBlXiZuNEIX7POYXFgHsY9GuIbx0bKXUHoMsTLOkJWJqKLJwNA6RnE3YCPH5
         Xskb/tsEox8+q7ThSaSrdjT/FMkG0rjAelVoG/u+KwLYO1nzvY98b8fwp0mE7FZT32aE
         PV7/y4bjldXVOj887fYGhK+hJArnln1ZZtLKSD1TPq5KPZYigE/P1cwkuXw2IKDdy6aK
         VKrg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:nodisclaimer
         :authentication-results-original:msip_labels:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=ZQfbRW7XPnFisWiLLDQ/I1Q4bbon0lad35y1PbUb57I=;
        fh=Gm+t5FFpvNE5fFt+fcnci8KtYmrdKgDUSBmfrx8gazI=;
        b=dj+1cPikodkutLjVAwUzTn+95QP0orRNG3L/YWxJny3FyWF4hd3mIJFsfOzmqS6BiH
         hWUjNunwJrW1/FFzoVRQ5yoFVP4PweR6ijaqe50JdiJAPuF2sSR2VOVgMiwt4ohRR2N8
         2QTkPRV0dZIHKo7DOAaWiTc6K3Sc3vomjBnzVZGjqK/i/9xe4PLnAPa+5zfLj9Q1WCdm
         sk75f2yjpgrPIH2m+XSjbmyCyEgeBzcuLViZs7MXdkoWTzBb01kaVsXSia6o0QhsH7Eo
         mZ5mlzJEiPx949b6K0fUpoe2ybxBnjQ9OvMsAlGoMLa6iKSkwr+RN6IPKjr9DHNPi7WT
         k2Ow==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=R6gQsQUe;
       dkim=pass header.i=@arm.com header.s=selector1 header.b=R6gQsQUe;
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from PA4PR04CU001.outbound.protection.outlook.com (mail-francecentralazlp170130007.outbound.protection.outlook.com. [2a01:111:f403:c20a::7])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50556b0ed2fsi294539173.3.2025.07.12.08.46.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 12 Jul 2025 08:46:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender) client-ip=2a01:111:f403:c20a::7;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=RK5yY+uF/razgEqxykSgOuYwRPV45QD48Vm8OcQYUnS/AxnpqdsMLpvyip6SJOq10NQ2gj5dS7XByngtW1UXhXeLYH9VgIXcwWvQjEsPONTi45frAsyJXocTEOAGP8WUqL9GQtrpJLaZDeKslKJNvn+oIAYHx2Uk+Pa46i7XWGpZWP0kyIV/OgtKL/kIPh7MYzTARK9SP4jsAp6GR3Q72Rqol+1AlAhzJmNYbMqIlovOSKCEVx6dcy62sAzfd4E5FCO8V7eseBToKLNQoi4ySdUJn5fGxfBo16GniqFBjJ5ECfyF66G8wlKIDmbl98gEb4bgsPWD5WAAoP1dkk2ggw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ZQfbRW7XPnFisWiLLDQ/I1Q4bbon0lad35y1PbUb57I=;
 b=XWoO6r7nyKvtF0AYJKBVQdQljpBE9x4Nk/b7NV/FWtwM3FXNDHCR7UlIvQK3xIkwN3lAqU2uyAHl0DS3QMEHHyavh6e4Ixd6sfUum/RAQdvR4Lo+sV1DZXaLwKNklFk9vzW47aOILmDwJcxX4LI8ZI9yOOi7g5LlkXcfImyNO8GlyjcHkWyvCmVsbR5BZo1MFuwdpI87eAp+Dje5mWj0Kj3j148hIRZyILECHXDWT0A8+cCKhxStflQeyr8KM8fC3qQ3hkkWH0Zig/YJfI2cFqREQ6Td10p9VU8MNxdQYYz/JYmx4+oWNq5qrtD6+vgyAqb7Act+sx5CY/GxrxfZ7A==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=sk.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from DB9PR02CA0020.eurprd02.prod.outlook.com (2603:10a6:10:1d9::25)
 by PAVPR08MB9235.eurprd08.prod.outlook.com (2603:10a6:102:308::11) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.22; Sat, 12 Jul
 2025 15:46:46 +0000
Received: from DB1PEPF000509F0.eurprd03.prod.outlook.com
 (2603:10a6:10:1d9:cafe::1) by DB9PR02CA0020.outlook.office365.com
 (2603:10a6:10:1d9::25) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.8922.27 via Frontend Transport; Sat,
 12 Jul 2025 15:46:46 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 DB1PEPF000509F0.mail.protection.outlook.com (10.167.242.74) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.8922.22
 via Frontend Transport; Sat, 12 Jul 2025 15:46:44 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=RcIsq1GUMhsrwSHVWvqsonBJ1euGVB2Ebfzv9aM2zUIg0kXoGIDtzwmDPPbrT1otMZl4604P2b0qahfiqeOiSa33xo62NxKfN5Up7WWgjmI+JHH94UYyYHG0xeVI8jcWDelGPjnaCOZppPRahrwMIRNGE0ShgfTLQESPB+HIZASkM4RhRiLzaTw9t7V24a+1Ok06Bm1PQS3h//RynTypRHTx0JaJ3JNciCtZoZApntCXFpC5EySSPAGJNnLlpQgVLx/+1Mp1s0aQLFfWw49KF3jq/0ybJVycmJa9AJMjibutjNVvJBAAOQuzydD77iuMjq3IDdqtwMLsR3jQw9bihA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=ZQfbRW7XPnFisWiLLDQ/I1Q4bbon0lad35y1PbUb57I=;
 b=KZVE4Tfjo2A1szNnB3cOzbD8LQ1UPAnYQae6G6jqtqFr+otAHdMngiZFNwTsrFiXIhRk18h5f8nzSy9dbQfYCxviDJrctDEsBSQ4Qm54MlpawJtAwrN0OE23Pj6YdPzaO0QafXLytOCZcy5XF2lSIarKqw46EK6PAgr/KedtKgK2ebObIuSV27Qxl5Yr4q1NZVnKpZpjm+waP+9vjLjFm6EvmYvbiX7HRWiEhZI+YFqQOljgS+DJ8sDZ4si9uO1RyCcFPYtpWDn9tDOiUmU8W1nv4qqCWaWIPwruGceBBw5YovxdvWqSiSU3haztK0vduL/4BJPfghrQ88vWwPLnSg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by AM9PR08MB6273.eurprd08.prod.outlook.com
 (2603:10a6:20b:2d7::12) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8901.28; Sat, 12 Jul
 2025 15:46:11 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.8922.023; Sat, 12 Jul 2025
 15:46:10 +0000
From: Yeo Reum Yun <YeoReum.Yun@arm.com>
To: Byungchul Park <byungchul@sk.com>, Andrey Konovalov <andreyknvl@gmail.com>
CC: "akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	"glider@google.com" <glider@google.com>, "dvyukov@google.com"
	<dvyukov@google.com>, Vincenzo Frascino <Vincenzo.Frascino@arm.com>,
	"bigeasy@linutronix.de" <bigeasy@linutronix.de>, "clrkwllms@kernel.org"
	<clrkwllms@kernel.org>, "rostedt@goodmis.org" <rostedt@goodmis.org>,
	"max.byungchul.park@gmail.com" <max.byungchul.park@gmail.com>,
	"ysk@kzalloc.com" <ysk@kzalloc.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-rt-devel@lists.linux.dev" <linux-rt-devel@lists.linux.dev>,
	"kernel_team@skhynix.com" <kernel_team@skhynix.com>, "urezki@gmail.com"
	<urezki@gmail.com>
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible
 deadlock
Thread-Topic: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Thread-Index: AQHb7EXBFvAGLGKalEKwGnsRygntW7QrV9yAgADhHgCAAACRAIACcr0L
Date: Sat, 12 Jul 2025 15:46:10 +0000
Message-ID: <GV1PR08MB1052126BB553BD36DA768C998FB4AA@GV1PR08MB10521.eurprd08.prod.outlook.com>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <CA+fCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz=HM1-DL71jg@mail.gmail.com>
 <20250711020858.GA78977@system.software.com>
 <20250711021100.GA4320@system.software.com>
In-Reply-To: <20250711021100.GA4320@system.software.com>
Accept-Language: en-GB, en-US
Content-Language: en-GB
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
msip_labels: 
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
x-ms-traffictypediagnostic: GV1PR08MB10521:EE_|AM9PR08MB6273:EE_|DB1PEPF000509F0:EE_|PAVPR08MB9235:EE_
X-MS-Office365-Filtering-Correlation-Id: 069e59f7-8f9e-40aa-f481-08ddc15b4d7e
x-checkrecipientrouted: true
nodisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|376014|7416014|1800799024|366016|38070700018;
X-Microsoft-Antispam-Message-Info-Original: =?iso-8859-1?Q?3ch/aYZHzMcHBbu+aV+t6QlPL5aaoAVY+XRxs3DA5zj7am4QIIB2pJS6ga?=
 =?iso-8859-1?Q?d/hZ6hsnwx0V1YMJIjiSqr5ZI8ln6DVbXUvfBQYdyrQk9Otp68vTc34VWv?=
 =?iso-8859-1?Q?QjjCCW4FeFZCeti/E7Zhrne+vK1Y6QXyGUy7j/AbftAM7iFWTCx9AX2vOb?=
 =?iso-8859-1?Q?Dqb2x/OHCtFTY77aOjY02UCa5923OhRxS15ufYpXbZB654uSOc258xS0Ts?=
 =?iso-8859-1?Q?PAGaVSf44AiBjI/bTM6gzYmIST9OtFNUmfY/dmWBfZc4igcm+Uh1aiBahw?=
 =?iso-8859-1?Q?z8pqFlvMM2HrSqytqy4Y/z4G2OsBg9plU7mvedEsNiu4WyvlSshsoGoadX?=
 =?iso-8859-1?Q?uY5MR0IksJCsO9zD119h8egj+8S6mt/ANfMkYo0fpiQB1iXATLYFoCZxo7?=
 =?iso-8859-1?Q?DlyYkjB71FKYLf617Y2NvebM++rTRopg8BgptXOWiT4nr5/cWL7vDYvYld?=
 =?iso-8859-1?Q?5pBtA0OEzopd7+uf0JMwbSZI9i1CZGu3/0VKEaMogSdXNefxuF31Qg2Hfs?=
 =?iso-8859-1?Q?NyaaRN9UWp3rofFrsuiQaebpll/i4XOj8s7b7/mWT/OTOFsN1K4XhsUBq/?=
 =?iso-8859-1?Q?g1rDAj/7KFajmap/R3YC8l2eVV8rGzEmp70PldgmGQy1JWGaHozXbnvbFr?=
 =?iso-8859-1?Q?u9v4sx02mYbtM4+LQMTbUucCiFxVV3MQlDHegSjqSSLWUVs+OPt/OSH4oF?=
 =?iso-8859-1?Q?5KJSJSONFFrG5DQGR11Pkc/GkhvNcvo9oL8t4By1doZImkv5ImJ2U1CEvY?=
 =?iso-8859-1?Q?YT7qXlocns+fM2DaLWT3WUSyZsJHgwUoj9MmsqmqCusfNPc4lh5EPsyrpS?=
 =?iso-8859-1?Q?HAMvm6+gZV8nRm+10w8p8ouY9VrC+uIWRF2JpnLsgid21Kc4DVM44Xtw1x?=
 =?iso-8859-1?Q?hwQCI/ks5C7CQw/ZF7Tjc/vkqw7MGLd/X1gCD9sGMGLp2ZJTe8yfFCx0/X?=
 =?iso-8859-1?Q?93iBaCUSI2sm4QmFSZul5+lcvsx8T8+v5NaDWIi86+AjpxmVg59s1bZuoL?=
 =?iso-8859-1?Q?xU5uosr6N5Ab4hbR2Gxa0uuEvI6YCBENXRdkRQO3s8fKXNWzsIz4F4TyKZ?=
 =?iso-8859-1?Q?n+Ce4B3cHGFn6jbUnR76nL4hqEWfQEhK5xZezr0DiFqnX1i1V7zFuylJzf?=
 =?iso-8859-1?Q?xhufvZuwGh8dGYUmVP12NsGUlon75ikof7xAETHXRsfa1icK9lT1WWmBYD?=
 =?iso-8859-1?Q?JqZXsiU2YbiuRY+QBcVFBuoyYFDeNumzUQh36/CWmSZt+xkEGF2OplLuFN?=
 =?iso-8859-1?Q?IffCjTC/VEn38lbsaLKSLN8SanSh4Or46Ev9FGnc0SYVqkoZOqbhTZ8khT?=
 =?iso-8859-1?Q?/EGIuJfpTKGjJ1Ea6anrBP/CHuAzox3C1PIeWLxnobHW3mlFp7ruu+IlSS?=
 =?iso-8859-1?Q?FACTwQ0X10IcE8RDkVg2aKJ+Hy5gjvGr0K4xxf75j8PCgvRBn4kWSs/BHl?=
 =?iso-8859-1?Q?hLiHrz23V2TITuTDaxJ3ORFNkaV+BnrHCOvyrhEYetxuIQCS5b7iVygncC?=
 =?iso-8859-1?Q?VZfYb/i4fdJ3jKGQuKv+9Gpi3csy55jiuNbT4RCePLlw=3D=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(376014)(7416014)(1800799024)(366016)(38070700018);DIR:OUT;SFP:1101;
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM9PR08MB6273
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: DB1PEPF000509F0.eurprd03.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: fda77e88-050c-4822-9ec5-08ddc15b3991
X-Microsoft-Antispam: BCL:0;ARA:13230040|1800799024|14060799003|82310400026|36860700013|35042699022|376014|7416014;
X-Microsoft-Antispam-Message-Info: =?iso-8859-1?Q?ajRIHZFXbiDB30QjqEW6DseUKoHABbsIKd6rUM7mKkWobyiMm68hX+Jme1?=
 =?iso-8859-1?Q?38e/l1+ewovxszfN4bAxfXNofE3qyLKJu/NHy3qaCrhA7jIUPpGPrnM3sy?=
 =?iso-8859-1?Q?jI4khDbt/0+gWusEyHxgYqbgIXPCyzgSF6/A3SvibcSyvjybtzXkyKy9BC?=
 =?iso-8859-1?Q?1OWK1EfJDT/39Neh55eBtl34u7TSXSsy06IlloSKYv4yKX31ua2+85NCdK?=
 =?iso-8859-1?Q?lg9ScDfazidjt5bLQfUKorglJtHBVO6nTrI1s+H7bIP0cemwPp49it3J90?=
 =?iso-8859-1?Q?xwZs55OicT5CoSCpn9dMNu84v646KIoHw4ATn2t0uz3l4OHOYmT/MaAKvr?=
 =?iso-8859-1?Q?n8dbzdh72VWZuVlovWNEngs3GoZi56awT1ctbwzatvGg9c2DJxsGwWuh4l?=
 =?iso-8859-1?Q?mxB4Vr870skdnLNrdHVG4NxFPCJzDYZcw1FDDpRhFecDCR/WbhUtaxmuf2?=
 =?iso-8859-1?Q?whUeiqMU6iFxFDJAykcR9biGn0UpdKj3cn4LX368XcTAsoIsBgX1rY0Gl7?=
 =?iso-8859-1?Q?J9qrTbjxLrkluNFUiGhZsWOBNpCgyrwrS23yKYYPFlIxibJAAXQf1oB3GM?=
 =?iso-8859-1?Q?uCC89HxuV+cDPMILUXpiHzcy+OiQHTExAdCh67/YkGtba705mbTyuD2Upo?=
 =?iso-8859-1?Q?8xPjrtKsaod+q1fids6Nbzd2u+R4O3bKqgswwrrPkrTHVWnVGH7oCqNVvf?=
 =?iso-8859-1?Q?i0wMuCznE2lKr4p+3hU97fS+rSD6K7Ol2b0PbwbNAQrJZhvZ7CdGQBvsGR?=
 =?iso-8859-1?Q?Itzn5gPXO2fbG/Rl01zTJpzktyZ+t2YFR/u0jjFnHXjA4uM4ysVLwM/x5P?=
 =?iso-8859-1?Q?GOKwyK1GZVPEx7RE7SK0rpf84ekdCjzzMEuQqtFGciywH7QMjwDEMqOvPx?=
 =?iso-8859-1?Q?VGoQHwlAbq86cW/T2EVQgEZ01R/lWDTPW3GL8wF24Nb77B3eucyv15T/A/?=
 =?iso-8859-1?Q?xFBSU4464SMiCsSELw00VK7AukHBVJFjecTw5wgXDE6SLpLarn0xpeE2P8?=
 =?iso-8859-1?Q?/JwiGGd/2LzwUJVbqWcW8Jed5FOILyvRFzzTlobnlbHGdcwSElwC0HQ0k7?=
 =?iso-8859-1?Q?3h8yw20jdxESdmQwBut6jWRsPRlDfogvdq7FS1tv3rVXKOD/91/UOcrbE1?=
 =?iso-8859-1?Q?EatBiz8mUwoG4GInwbDG7Rk6BBIwE+V6lqfoPqz9bxrapFNEYCwiXG+UcN?=
 =?iso-8859-1?Q?+OcZUsXQckj6O87RBjTJe6raXr5+Stbgi73nVAFNxTR2Xp7SNICcyWgQBw?=
 =?iso-8859-1?Q?gqu6wNn0EVNiGa124Mshk8vBWAiMK4MJXtGE9k+WkcF1iS3PrifSJVaYgR?=
 =?iso-8859-1?Q?suc3CFLIegnTqUICXN1lAUaRaBNI32M5JlFjMOWgepjxLitT/yiNablMzJ?=
 =?iso-8859-1?Q?ExFMwClm+caAWXW/nc8A3aP3eCZf9cpkdJcLqImdqoY42xhpGlvv1vLCrJ?=
 =?iso-8859-1?Q?mp2pCv4URqjWheidEUKLm6ZRwiNgGINhYLGMiKiQiA1G6ObhLBiO2gjmeG?=
 =?iso-8859-1?Q?dzfSBmGj4niP3lc8wrqOoQU01M4gUJOJF058sClULaPHVYGy3567Pjy0vD?=
 =?iso-8859-1?Q?UgO+y++qGJX7X2u9bD6O09ifgXlD?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(1800799024)(14060799003)(82310400026)(36860700013)(35042699022)(376014)(7416014);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Jul 2025 15:46:44.1856
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 069e59f7-8f9e-40aa-f481-08ddc15b4d7e
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: DB1PEPF000509F0.eurprd03.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PAVPR08MB9235
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=R6gQsQUe;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b=R6gQsQUe;       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c20a::7 as permitted sender)
 smtp.mailfrom=YeoReum.Yun@arm.com;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Hi ByungChul,

[...]
> I checked the critical section by &vn->busy.lock in find_vm_area().  The
> time complextity looks O(log N).  I don't think an irq disabled section
> of O(log N) is harmful.  I still think using
> spin_lock_irqsave(&vn->busy.lock) can resolve this issue with no worry
> of significant irq delay.  Am I missing something?

I don't agree for this.=20
since in PREEMPT_RT case, it has the same problem.

In case of PREEMPT_RT, spin_lock_irqsave() becomes rt_spin_lock() which is =
sleepable.
But, KASAN calls "rt_spin_lock()" holding raw_spin_lock_irqsave() which is =
definitely wrong.

But as Uladzislau said, without reference count manage, UAF can always happ=
en.
IOW, If KASAN to dump vm information, I think we need:
    1. manage reference for vmap_area.
    2. find_vm_area() with rcu version.


Thanks.

--=C2=A0=C2=A0
Sincerely,
Yeoreum Yun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/G=
V1PR08MB1052126BB553BD36DA768C998FB4AA%40GV1PR08MB10521.eurprd08.prod.outlo=
ok.com.
