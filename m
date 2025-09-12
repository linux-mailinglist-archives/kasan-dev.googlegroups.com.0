Return-Path: <kasan-dev+bncBDZYHIXQT4NBB5XFSLDAMGQEDB7YY3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AA0BB55A79
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Sep 2025 01:55:37 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b4d3ab49a66sf3327700a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 16:55:37 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1757721336; cv=pass;
        d=google.com; s=arc-20240605;
        b=VW8jpLkeZ80SvZt9hY3Z3NqFvnMp/hPmSxopu10wzk1c4ge6WYLl8qWItCtydrcT5Q
         4ViqW7wtXW8xBgDbpgDg6CkTCQU3m3MyLtlHv8VUpyI6UxB8i9PyaAaTpuwlm2ydy0Hh
         rG0s6PiIirKyygBDdk31ToflDmUJE9rFEhKeUyxKDGI8pL+lZpPjJmQqNJCfesKdGSDR
         UYcXLmy4vjo/KJDoWm7zK9k+2E75QtRWOW2GzLd49KbbTUFpv0T7ozhfRi0g7j1rz+57
         xl+5Gku9r8JnYnfAor721dBXNcq9KatCgbM88wi7Q1MDhHk3W0l5tcmo0tnK/7spuWH9
         BUiA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-transfer-encoding:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=Ws0huwFqnW9/go9FWKlgi1RdGse2Zradu9pglv9MCHQ=;
        fh=e6hwIAJzSJgVmcr7GZ33QFbVSrJF/DYazjj7w0SFSO0=;
        b=iyxBjJLSoTCh9TAWfZSRt8oanRfVR7KfgBc3IRC5pe0rYE3FS7hZKR1Sg0SMvHWHlj
         kr6spST2CL2aBOxG0XiUyYlGu6BtuKW2q0yabkKnVshk4qcWH+xJnbeaNmwkXzGsC/dT
         1auc03l6M3y69yGf9XSeq0R1IHB2olJkJNt6nhQNUCIltDfDRk9e772hfXXb/O8hzRn/
         FkUMnFTmV2S3QWoti40A3iVVy6/Ks2T66w5zCzzksbm32kFyq/WBam9w7Z/Hsl7lUiHf
         La6muNo8aNOw9uq3+vUgtpUtgH7ueijwbJdkZaGYt7f7F7SoUowwejgAvBU+4g1EBzBE
         bJGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=LdODTL6D;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of balbirs@nvidia.com designates 2a01:111:f403:2405::61b as permitted sender) smtp.mailfrom=balbirs@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757721336; x=1758326136; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:message-id:date:subject:cc:to:from:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Ws0huwFqnW9/go9FWKlgi1RdGse2Zradu9pglv9MCHQ=;
        b=M6A1LSfvqlV2FPI3btYuNhNFK8WsIKWWIuIcZN0QWflvYOJpPfqGYruj917cimwcmM
         5gN/OHdWXjFh8uDvTrpuIqZLuNd2L8xT2oB3VGcDvunS6YZjtrw2v4hZUv9oUd1laXVb
         Gv8oo5E+i36hnHt8HPUOHHen0x7JClrqV9YNJCkgeZzGIiQbmKvgg66A+c8FwAK9lSMx
         Y9taYWUSeB0pMINYpaj67hLASJJpx/sqhP5wnzFw5lhug/wVqBjPgBn9shH4SHgJc8qy
         SOe2hGEB0EWkP66bYJXgFV82KnZ/6+YIhyBiTINb2nsUQtka6po1bFPrkSF8xU9gIXES
         4lCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757721336; x=1758326136;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ws0huwFqnW9/go9FWKlgi1RdGse2Zradu9pglv9MCHQ=;
        b=bo6wnMCPDyBHyemoJFO0CBSRhWczi0uCtKXJmYhk97rEEv3EQ2dqxIgXqVdo0e6fVv
         58JBWxszyLtDfcfAjYZ6WldS+Fn9vlm3RI6SGcnlMlKFh9wrLIvsPUQ8uYOtLsq6l1S0
         N4DBmVojsmkmSeUb70qVoHDYIDoMktouHOvIhR/IaXya4dlYV4rf8bsNzXPK6xWs6tjQ
         PjRbJOTFPIqcYvq+avYolg2oo/7MHQBusqyJkkaAD7gbhUQXa07MML8Exyz4O4LBAj7B
         woMOBt8P6yzGQA4G1qtlqRPgTgZ1qAqvHg0G4v8NqE+6BW0pEdoyboi8jMxbn9gTb99a
         9z0A==
X-Forwarded-Encrypted: i=3; AJvYcCX8klc2lNdi5sUzJLaZKTwPI8xzOVx+52LKfUq3uSFY2mK+qQldvXF9PqBPBYisqk2r7g7wfg==@lfdr.de
X-Gm-Message-State: AOJu0YysvxEss9qmaDF7m9qigubobvp0PifwfOr3fK/9f7yR8vqDGxsj
	R9EIUiWJePcIUMOqWV4V6PZWjNX/5zA9wnoiIC5iLf85x9KM+s/Uo/rF
X-Google-Smtp-Source: AGHT+IEMC2VoVPPMt3nm4KPcjSjzfV7kXboMZLdyBO4zYyEY3o6CgwwEITzxVJynWMQASAqNEe/EOQ==
X-Received: by 2002:a05:6a21:6d9c:b0:240:dc9:71cf with SMTP id adf61e73a8af0-2602bb59374mr5991957637.38.1757721335595;
        Fri, 12 Sep 2025 16:55:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcqImflZfND8en8KKiPTha1lKsKaQVxiszjSa8lPQUnPg==
Received: by 2002:a05:6a00:781:b0:772:5a1d:eed4 with SMTP id
 d2e1a72fcca58-7760513a4e8ls1959705b3a.1.-pod-prod-08-us; Fri, 12 Sep 2025
 16:55:34 -0700 (PDT)
X-Received: by 2002:a05:6a20:2449:b0:252:3c5e:45cc with SMTP id adf61e73a8af0-2602a593266mr6163970637.19.1757721333831;
        Fri, 12 Sep 2025 16:55:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757721333; cv=pass;
        d=google.com; s=arc-20240605;
        b=ls5AyCXWyTG+/iqaFIrpRRtgGW8OzKgU+10LkwNMvyqdZO5JQiCkjSVZ2xCl8KliaC
         TMgopE1shYoyLCnDgddSUFTAj7mq76GZ4OFVSgKp3k7pyTEVUHzCDZcVC2P+uWPR+7Rh
         70PL5RWovDaFuLa0KpK32dhfkJh5EAl2nU7K6Gdb95jlDc8J5n0mh54XDxlGAbd+hIcz
         mOEWNo4++IN3NHB8TZVfiq28/aCRlnpsFgyBD9KkiP/IKI7bdri1LiMYErshC6rmEqeh
         JiyBI5Du/PRBGoR68g7xfA5Z3ALEhuUYUBVJXZ4VMz360DA2EEpYpEKQfSEKYH8tiEOn
         Ljxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/EWc0bDIZlBDvJuzD6yEcZlHIQlaXhobPioEBa7RoZQ=;
        fh=J7FB4FkpNNKQUNdH06Sspe8QMH30sKMQzTxTC8Pr9DQ=;
        b=YpBJKOCLhPqO9EMRy4wdULfmLRHgXfJeIExZJgNkmKw5vQ+GvqAVB3KAtlp1s5+Du8
         v+mmpAV9GZkqVSu+NC/joUB2kpjQUf6eaayKMbiHR+otIf8iC5U7nQmEmcc36aFA+Hdx
         gM/Hud98LgwgUgxlvakadnkxNrlw3T1qICAigySPgHbOvv4sbDYiaFYOoSncb3DN+v0e
         eF97MfQuozx8QyFXKpcfJzIoSkwJb8wiTE/1c04qhhZwh4fgDl/i1S3oH34My7ZFlAxQ
         634vR4N6J0r/mMMckivBpxJ6GIL8kS5USgSYkKQet+6u5Eeh4GuzBSM/Ccc2qQpXGZIc
         LnhA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@Nvidia.com header.s=selector2 header.b=LdODTL6D;
       arc=pass (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass fromdomain=nvidia.com);
       spf=pass (google.com: domain of balbirs@nvidia.com designates 2a01:111:f403:2405::61b as permitted sender) smtp.mailfrom=balbirs@nvidia.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=nvidia.com
Received: from NAM02-DM3-obe.outbound.protection.outlook.com (mail-dm3nam02on2061b.outbound.protection.outlook.com. [2a01:111:f403:2405::61b])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dfd0b75a7si57077a91.0.2025.09.12.16.55.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Sep 2025 16:55:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of balbirs@nvidia.com designates 2a01:111:f403:2405::61b as permitted sender) client-ip=2a01:111:f403:2405::61b;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=q6Lm8grZjnTm6EQv15uLI13ooIoTsHGZtc1/j1yvYjGmf1gbFhkGgf5O/wbfvNXEa58JA126rV/Xo1LSWH7NJ70ot78F+rCKKUSOZChqWTXcWlaDt9hHEKpkHZV7VoLdg6gQt9VhuKUuTea5Bj/gjnhEiJfc7SqDHZEjjaGcHuXZNmfLIoXvAF/wr87D3PiNXX5R9JvPk1ItbmjKEGE7gQtutDjCma0XCvB9dKVTRfMkEr0tHfzMO/2hi2oSAbrQb2CSVyZZ7WDYDKb+2weWgl1tDHtGR852/zYAzL+KGOI3phXzwAq6Q2ztR5k1Wy4Bm+nz2s5c5HHv43cjeOhTUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=/EWc0bDIZlBDvJuzD6yEcZlHIQlaXhobPioEBa7RoZQ=;
 b=Rpw5wgd/Phh3nbgQV9qm+s7n0+P1eE6H4Du6HxOC+M5i7O5JUHuagypneEnHQ/cX1Jkg8A5LUrLwMU+cjYDADL7xfO2p3K0SttLVCWrO8+ymWcybdSKS7aCLHinK+EA8V+g51eX532IS+thFiCZGjg3Wms/PHzXRVpqwBJqbjfznBS6w3TFCH9w/z2bO/KDiuAUTA45O/9lCZe9jXJ8jgmSDG0BQZspzHwpVLKI8I34L5v/g7eWLhPMRPv47xhEh1u77fsfwlUqs0BCU/c1931vzmNn4iRFGHCFc7V5/BVPjx5QwtSqSWRoZRzKtjThS/OBLZGldZeVrPsNuGs2DIw==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=nvidia.com; dmarc=pass action=none header.from=nvidia.com;
 dkim=pass header.d=nvidia.com; arc=none
Received: from PH8PR12MB7277.namprd12.prod.outlook.com (2603:10b6:510:223::13)
 by DS7PR12MB5958.namprd12.prod.outlook.com (2603:10b6:8:7d::20) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9094.22; Fri, 12 Sep
 2025 23:55:31 +0000
Received: from PH8PR12MB7277.namprd12.prod.outlook.com
 ([fe80::3a4:70ea:ff05:1251]) by PH8PR12MB7277.namprd12.prod.outlook.com
 ([fe80::3a4:70ea:ff05:1251%7]) with mapi id 15.20.9094.021; Fri, 12 Sep 2025
 23:55:30 +0000
From: "'Balbir Singh' via kasan-dev" <kasan-dev@googlegroups.com>
To: agordeev@linux.ibm.com
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	akpm@linux-foundation.org,
	ryabinin.a.a@gmail.com,
	Balbir Singh <balbirs@nvidia.com>
Subject: [PATCH] kasan: Fix warnings caused by use of arch_enter_lazy_mmu_mode()
Date: Sat, 13 Sep 2025 09:55:15 +1000
Message-ID: <20250912235515.367061-1-balbirs@nvidia.com>
X-Mailer: git-send-email 2.50.1
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: SY6PR01CA0158.ausprd01.prod.outlook.com
 (2603:10c6:10:1ba::6) To PH8PR12MB7277.namprd12.prod.outlook.com
 (2603:10b6:510:223::13)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: PH8PR12MB7277:EE_|DS7PR12MB5958:EE_
X-MS-Office365-Filtering-Correlation-Id: b63226e2-972b-4bdd-5e83-08ddf257dac8
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;ARA:13230040|10070799003|366016|376014|1800799024;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?ZEFhZ1k0bnUyUnZGaWNvdkg4cVprS0NHYmpIUkFTTWFLeStxV09BWVRKYVlE?=
 =?utf-8?B?TUg4aTB3dDVlQlVtTGt4bDQwNHduSldtTWN1UENVZ2s2K0cyM0o4aFJUazZO?=
 =?utf-8?B?TC9rN0gydnFyalRRS3Y0TWkzWEZqYnF6SXhJelFpZ05WdDAzdmRrRzh4K2c0?=
 =?utf-8?B?WEVGZlRkM3VjbWtMdUJ2ZFRyaHFVak5QQ3ZHUHE3YXQ0Q0dkbmxZZ1BnOTEx?=
 =?utf-8?B?b3dHNW9WZTNPZHFQNDU4TFdiZDMwSlk1Vm1VV1N4L202UnJndXZERWx0aHlY?=
 =?utf-8?B?WE5vcnlVRHFCYk5iT2NtUU9wVmYvNS9Wd1FHR1QrcEZYdnFyVVFaUDE3QjNG?=
 =?utf-8?B?T2VNWUxOM2IxUXBTWGlmZHd5QkQ3d0tSbitmdkNMVEowSTdvajk0d3lNOTRz?=
 =?utf-8?B?TElVMGk4bTR5ZWp4UmFma1kwcUFqM256UUkyZ1VURXFTUy8wMHlEK0hpbzIy?=
 =?utf-8?B?L3FrejRtZHV6em1RQW1FdUxralRFRkRsOVB6emlhM0JhMC9JbW9SRitkK1pp?=
 =?utf-8?B?WFJNRHRsSlVyVEhXUERRL1JtdkNLS01tYjNRdGlXeHE2K1RNNGdLTS9UVS9E?=
 =?utf-8?B?ZHRqT1Z5VXBJa2ovT3diTDhuRW10ang4OXY1bEFMbkc5Yy84SDR3bzJpWTNI?=
 =?utf-8?B?Wkd6WHR1emI4OTNac2tJUWsvd0NTc082RFZDcVNHYVg3dFBzWHdyOXI0elFG?=
 =?utf-8?B?ZnQ3RWJpcTVuVG15MlVEd2tqbTNSVFg1Q1lMR0h1QTdrak93UVRaSkZuN3hQ?=
 =?utf-8?B?TWNRR2c0QTJadzdWYmlyZG1mS2I2Ny81emZ1REZYRytMQmRhbjRLbGliRDBu?=
 =?utf-8?B?UThJL3NNNmNEcHB3Um1CUldJanZOSXo1enRucmlZVUNmc3lpdjFpbU95c05N?=
 =?utf-8?B?ZUowMzVyYVFiY1ZYSld4bXpyOUR6QWFZaVpUWGJyM2NKRk5tWG1lOXEreXhp?=
 =?utf-8?B?UkdhQWdmYmd6NEtXNndkMlA4TFZZczJpZ2ZwVzk4RlB2ZHJvSjlvMk5GSERZ?=
 =?utf-8?B?RFVpK1RSZlFHSVJDaXdDbThHVFNCdENjUFNtd0k5RE4xcVViU3k2VFJ3UnJs?=
 =?utf-8?B?ejN4MVFVRDhmOTRhakRGRnB2dVBySVBjRWR1emo5TmlIWHlFdmZEdzdReTgx?=
 =?utf-8?B?b01OMkpzbjMvbk90UGFMOVpQTmVCbml4WUdRM2hSWGFuS0paWTBBa1lZVTZK?=
 =?utf-8?B?emNUMW12bDh6OWRYd0NaNExKbngyMEp0eVZDS29VTEMxVlV1ZDZFUks0cjhB?=
 =?utf-8?B?eXBVZTFUZHpHQkY3SnE2UmlLS3FFSG44U3Rtem45bkhFaGdZZHFCTFZLbVkr?=
 =?utf-8?B?UEM4U0RhSnY3bkpNSC8vbjRqWGMrRzJzSHBMdzZyRmNROUxnL1VSUUJGbERH?=
 =?utf-8?B?M2VaQXpRRnA2U2c5RFZjRHRiME82S0Z6SGd0RWdRTHhNWW9NaWpENi91Unpy?=
 =?utf-8?B?cGxHL0NSM05JNHlRaUpNOWIyVStnSWkxbTZoTGc5TWs0MDRlOHJrbUhsemRk?=
 =?utf-8?B?QjBHVGY1bHNodWl6YTdlcjA3TUlMUjJtdVQrdkFUSGNJNnI1U2x1ekFjWjdV?=
 =?utf-8?B?Zjg1TXFuUUVYTmtXUXBGSnBwdHJWWjE2NVcybmNSOXN6b1IzNXE4eGJaeGp0?=
 =?utf-8?B?djZkdVpBbExCRHl6WFVmajBxdUFiQmFveWJ3eGtTSEQ3K1g5UmxPbS9Jb3hq?=
 =?utf-8?B?R2M0R21DV3Q0MUFEL056Zm9JbEQyVXo4NmRscjduZVB3N1BTRVIrWjhlL2NF?=
 =?utf-8?B?K2pqSnNxWnJEOWd5UFVqLzVWZGVxaXo1MTdyQk44Z2tybUJWQS9DUzVOTkJ2?=
 =?utf-8?B?Yk91czg3R2tYL1dQa1pWRjZSTmVNTjltcGZuT1E5SndibmJnT1plRmtBdkF4?=
 =?utf-8?B?a2lJYWpZSnd1SDJ1WjcrTStBSzFlcWdQbzZsZjlqNzJoczd6MFlYSm8vWk9I?=
 =?utf-8?Q?TlL8nAkMBd4=3D?=
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:PH8PR12MB7277.namprd12.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(10070799003)(366016)(376014)(1800799024);DIR:OUT;SFP:1101;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?Z25RTUdFOUpBSlBJTGV4MkR4YXZhT2JBeURvejhuWmE1TWE2T290S1ZMMmV5?=
 =?utf-8?B?bklTT2ZNeTFaV2xpOVhkSmt3bTNPQm1xUjUxRUgveDlMZTN1R1ZsV1F4V0Iv?=
 =?utf-8?B?K1h0dVdSZDNjUVNxdHlOeXYwRkw1M2MveENxY0lzSlhMK0QzUGlkWXZ6ZHEy?=
 =?utf-8?B?d2U2RTBaU3JJc0tWNDEvSWVuVHNYUFZaaEw0MjU5T29kZllVNDJtV05iTlNW?=
 =?utf-8?B?SVhmTEJiSmZ5TVUvaW9kS3E0MjRyYnM2YUpCU05mdUludDZ5L3Z4ajJOMG1k?=
 =?utf-8?B?VXdmR3ZrSXFzTUQyUVU3V0hvQWtrcW9sN2t1ZWxGWE5PY1NCdk5oeTg3Z0tT?=
 =?utf-8?B?M21YQUIrTEljd3FoZGFQQXdmWkloQXRrSFBxRFMzQ3RUVzNXZ3BWV1NmUHZV?=
 =?utf-8?B?NDlTejZEOWx0NHI3UjhxRFJ6c29Vc0pCeTA2Ry9xNzFJZzRsZVdMTm14Qjh2?=
 =?utf-8?B?S2dSTWZRS2lZcTNaSXhNd1hrdElNVkhFZW1ZRU9ua2pEUHNxT1UvYVU1TmYx?=
 =?utf-8?B?TUFhVzkxUlFjb1ljOEp5WjhKcGYwUkZYTUpFNHdyR3RTOUZPeFVrN1lsbEtx?=
 =?utf-8?B?V1FjU0pWSU1ENXFYUHk0UGVtdmIwMzZEUlJDMDJmWFFndWxWbmFNTHFWQjdW?=
 =?utf-8?B?UG9nTnRLY3FuZ2NPNDcyc2ZwVVh1d2duaFBXOE85L2d4YUl4OHhvcnlYQXZO?=
 =?utf-8?B?dVpCWWFTRzFWb3pyN1MrNjJGcHVXbXY3M293Yng4QzVhMTZnVUVGeGRLbTJ4?=
 =?utf-8?B?cXRocGUyRGwxYlViZlJBL21wZk1hd1Z6WFcrdGRFL21CQ3pwK2lackRsQXEv?=
 =?utf-8?B?Y0FUQ0tGMkIzcmU4SGhSWGxIRnBZMnhKY0hKRzYrT2ZRYjF2cXJ4c3pNdldD?=
 =?utf-8?B?djdVaUZVZTc1SVg0aFVXZzczVERUZTR6dzlUN3BYRGQvRFM4YngzZkM1Ukdi?=
 =?utf-8?B?elZ1cE5OOTNZYVpGODlZRUkySWNPUEl6d0NZOFhQME1CRUo0RGtWODk3Mytk?=
 =?utf-8?B?WVRVblhRaVlzeFNybEhDb2x3STFJTURscndFWHBvU29IbFEwV3oxR3VJcmw1?=
 =?utf-8?B?cVFlbHJmc1Y4RVg0anJiUlNzTHIrOGRVTXdRMTcvTmVGV2RkaTZWVDJKTEZm?=
 =?utf-8?B?OGhlWDFldjBzUS8vQ0dOZGtKWGZXeDJnd2tCcnJZdzVIVUc0WG5neDhxSnQx?=
 =?utf-8?B?S3FkZ3RWRTR3RXY0a1dHRjZnYmZ2aGM2MnYxSUZlOS8vSCtNUzdLd2xPWFU1?=
 =?utf-8?B?V2I1cW5FcW5DS0VibElEQ1ZHMEVkWUFzUUE5UTVFSDVjd0ZFZmZkb0plbDdP?=
 =?utf-8?B?TkI3WmpweFk2NmtBN1ordnpHVGo1TGVOa1A4eFV4Uk1rZ2NZT3V5dHZiVkZJ?=
 =?utf-8?B?QUdLZTVrcXBVd091eGRmMUs5OHlXS0ZvV0ZQUjVzSDFuRktCUU1ob09mcW5N?=
 =?utf-8?B?eFhYbXE3M0VKZjZMT0cvUHFTcXNpK0VnNnlxaW05KytaQVVjOGxZVzFqRkZZ?=
 =?utf-8?B?VUtnemJocWIzRVZ5RUpzNnIzWVduUEkyWjJSOStsdVh1dmRRNklZYXdCZVV4?=
 =?utf-8?B?UEYvUjZTQkE4dWw3S0JvMTlmaXVucWp4ZXVJNUs3elNTUUZZU1pZVmtXRVhN?=
 =?utf-8?B?S3FrVlZjQVd3N3l2bGJBcmhJWVBrS1ljVlJSdDBrOEhNOW4xQzcvRFRXMUdz?=
 =?utf-8?B?bTBkZHZkUHFINi9KdVA4d0o5ZkVPcnVselpIU3FDNzZEbXFaMzVvaTIvY3Rw?=
 =?utf-8?B?bFlQWmxySkpKYzlLSm53bzMyNlVyZUF5TnVPWTFXYWoxUDlUS0hKYTZhU29R?=
 =?utf-8?B?MnZOZDVOMWE5dHNUUU8zVEk2bUQyZTVDOXdHUEZJeHZCUzFVcW5RUUR1ajR6?=
 =?utf-8?B?M0hlckVjNEpSODZqeExGdWRmK0ZsQWV5Umg0SUljRnFlZjJmOHpYSFZJSkNJ?=
 =?utf-8?B?K1h3dkY3cWtUT0tyNnIzeWZhajBVMnl4eFM5a2FGM09HbDlBbkw3TjRYL29y?=
 =?utf-8?B?N3VFMmVtcDRTRE1RRGdlcFI4NzYxS081bE1qNmNXUGJ2NTJNRGFmaEJ4UTFu?=
 =?utf-8?B?QTNlaHVCKzl2bldlWWsyNEM0Q3FGQ3FLcHdKZ2UvU2liVUZSd1owLzFxaWhs?=
 =?utf-8?B?S0I1K3g5VkxON09jYTdYbXc1L2x3bGkybzVkRU1UVHF1YTI0NEFkenQ0cGlj?=
 =?utf-8?B?R3c9PQ==?=
X-OriginatorOrg: Nvidia.com
X-MS-Exchange-CrossTenant-Network-Message-Id: b63226e2-972b-4bdd-5e83-08ddf257dac8
X-MS-Exchange-CrossTenant-AuthSource: PH8PR12MB7277.namprd12.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 12 Sep 2025 23:55:30.4182
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 43083d15-7273-40c1-b7db-39efd9ccc17a
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: N1ggTZ7GKv53656Z9CLmPhsCpvr0I3wLF1RX5dpMZF3jf2ZeUQxoFbxRl2ovFEnSgW24JBee5CJRgaeDbJxitQ==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DS7PR12MB5958
X-Original-Sender: balbirs@nvidia.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@Nvidia.com header.s=selector2 header.b=LdODTL6D;       arc=pass
 (i=1 spf=pass spfdomain=nvidia.com dkim=pass dkdomain=nvidia.com dmarc=pass
 fromdomain=nvidia.com);       spf=pass (google.com: domain of
 balbirs@nvidia.com designates 2a01:111:f403:2405::61b as permitted sender)
 smtp.mailfrom=balbirs@nvidia.com;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=nvidia.com
X-Original-From: Balbir Singh <balbirs@nvidia.com>
Reply-To: Balbir Singh <balbirs@nvidia.com>
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

commit c519c3c0a113 ("mm/kasan: avoid lazy MMU mode hazards") introduced
the use of arch_enter_lazy_mmu_mode(), which results in the compiler
complaining about "statement has no effect", when
__HAVE_ARCH_LAZY_MMU_MODE is not defined in include/linux/pgtable.h

The exact warning/error is:

In file included from ./include/linux/kasan.h:37,
                 from mm/kasan/shadow.c:14:
mm/kasan/shadow.c: In function =E2=80=98kasan_populate_vmalloc_pte=E2=80=99=
:
./include/linux/pgtable.h:247:41: error: statement with no effect [-Werror=
=3Dunused-value]
  247 | #define arch_enter_lazy_mmu_mode()      (LAZY_MMU_DEFAULT)
      |                                         ^
mm/kasan/shadow.c:322:9: note: in expansion of macro =E2=80=98arch_enter_la=
zy_mmu_mode=E2=80=99
  322 |         arch_enter_lazy_mmu_mode();
      |         ^~~~~~~~~~~~~~~~~~~~~~~~

Fix the issue by explicitly casting the use of the function to void,
since the returned state is not forwarded/retained

Fixes: c519c3c0a113 ("mm/kasan: avoid lazy MMU mode hazards")
Signed-off-by: Balbir Singh <balbirs@nvidia.com>
---
 mm/kasan/shadow.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 60b1b72f5ce1..347e02a70892 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -319,7 +319,7 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsi=
gned long addr,
 	}
 	spin_unlock(&init_mm.page_table_lock);
=20
-	arch_enter_lazy_mmu_mode();
+	(void)arch_enter_lazy_mmu_mode();
=20
 	return 0;
 }
@@ -494,7 +494,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, un=
signed long addr,
 	if (likely(!none))
 		__free_page(pfn_to_page(pte_pfn(pte)));
=20
-	arch_enter_lazy_mmu_mode();
+	(void)arch_enter_lazy_mmu_mode();
=20
 	return 0;
 }
--=20
2.50.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250912235515.367061-1-balbirs%40nvidia.com.
