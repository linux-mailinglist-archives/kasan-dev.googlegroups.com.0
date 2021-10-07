Return-Path: <kasan-dev+bncBDRYTJUOSUERBXGT7WFAMGQESQ3XMTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 57340425F5D
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 23:42:53 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id c42-20020a05651223aa00b003fd328cfeccsf5546430lfv.4
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 14:42:53 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1633642972; cv=pass;
        d=google.com; s=arc-20160816;
        b=gg8J0F+TpDJhhyeU73Buec6uaklhRUzLWPM2pC+HexiHLy95QoG1Cki8xdnL21ffD0
         LYCxhDebq07hRwnxrKsfFcjbJyTefMjblXJTH/6aYoBnJIDnkl+Fzhx+cvvecoA88kQb
         REGTnUB3UDMM+J9y7Y/NBhNXN3mAbwBMdRj1A3s1npMt6LrRko3N3bjqeKBSI0+0dSoo
         43PDg3sQLVuNsrU9WmSABYDki8NTKTmJTecz79v3D67EyQPojyLH68n5l6nT+6G4CCyK
         hJBo/QEuL+kropIg0hlGcS1S6+CaBlhPoVWX9dWp1GCTU8xM9bJpA+R9hvK5VBGEcnZT
         geeA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=X6KF8ItxPOV0/PayJ8P6Fh6KNDzFFYqP51gaj/iGg0s=;
        b=N/f/bCTRy/8B3Pje3CzBLf5B986dylnP1+JYNhKBmKcCJ1mY4N1gvRPIJEbi49Qymk
         1LFdLWNA7JWdswM0ax6ijUDgRSxsSTmMGgDQQXjO3oRFcVw++O7ZOuyrm/ITStF+CKOR
         n//CCo/zxTVYPJbidShoBI5LSr48JSI4kx/n2WBfxLv6oiH1Ci0OdZJuBs7z1RnvH7t5
         9jjP5Qtsxe6+J423s95ekuydAIoKqURiaUSWsoikJgi/VswjkdZ+mimzVpoTxqHfsZaD
         sP/D4+hhS1s7vsg1D+JehET0EHBtZyg0SYrkONnL7L4sS3lpY5wvxSErEmkyZy/3tiFi
         18dw==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=Mn6Y2KeC;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 40.107.11.133 as permitted sender) smtp.mailfrom=gary@garyguo.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X6KF8ItxPOV0/PayJ8P6Fh6KNDzFFYqP51gaj/iGg0s=;
        b=j4GEhOx9WP6vakHPulRIM9CK6YuBf9Wg11jnXnB+sLha0/8GIOXzd1eblrO2Tnx5So
         14kjNWHAwPaWk6lzk39ACspKg5wFAWvx3YnIBAvyUYV1INuF5p5wLhNnbJz7Q+o7o45B
         3JV28WALkBwGCisbpxjD1t66Iwr3Lh+2Z6H3uuVz2rpivP2eyXNMoFH2fLsn1HN1l7lH
         s/MwkZXF8UQfbt/moPbqDU177N7DAsyWP9+PGmitgh0A1ckQsiSS/iueDRWo+ggrlsnN
         TMISlhA2tDlT3ZunQXWIJrQRiPA53TuRjhbC1bg+dg84XA1CQN64CbfBgRjcWn944JjG
         6PZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X6KF8ItxPOV0/PayJ8P6Fh6KNDzFFYqP51gaj/iGg0s=;
        b=N2pdZhLxmUqrLT9N+vGhXC130klX6DJjAiJGI1YumW3uI8R8YsvpOCl6cGYt/S1BiW
         IlxxPVEq1NJD0oVLwl9ZC0JQp0X0915G4Xm+b1Zsff456RnspmTqR4tC4+rLj0uRozN1
         EwMCh1f7DQ39Ch4JFkZFagsASlCFUv4Pw/cJaHT0sYiWaKUIM+Syvdn0QzLAQ2TSnh/E
         lAVF2+jN8p8YANE29/9Ap3o8OzwhxYat+6yIHl67pwSXrDD1Hi7jfm98jhX5PxiQEEoi
         t6yefQnV1fxKujpcdKl3HFpjuU3XDkZyEBCQcC6DZ068s2n0BAVHReOQ8heOGcL196G+
         XvHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533D7SmXHmPZivqht76t1pmlpIrvtGF1poO6ZBXabV1y0nQeLe7d
	R9wT4pKtxC7385olLSkaSHM=
X-Google-Smtp-Source: ABdhPJxRrkvIJOI6yexhs1ZfCqr5bRvF323SxsVGt5/HnlybzUy8JDOzOx0hArmf2UTNmHWEpjiOug==
X-Received: by 2002:a05:651c:44f:: with SMTP id g15mr7421201ljg.396.1633642972737;
        Thu, 07 Oct 2021 14:42:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a801:: with SMTP id l1ls240699ljq.5.gmail; Thu, 07 Oct
 2021 14:42:51 -0700 (PDT)
X-Received: by 2002:a2e:541c:: with SMTP id i28mr7095846ljb.377.1633642971503;
        Thu, 07 Oct 2021 14:42:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633642971; cv=pass;
        d=google.com; s=arc-20160816;
        b=gzCCkDd86fBD0CuyqPNu/yT4tw9u8gH9pflDW8uwsCVdoBJQhVz77iX3qNF/EuPWRn
         dc2ySfKhf6vRH8ca+2/aeWaADBpHL1pZvLQn4y8/dKuKPOhHsYHQ0asSpwWPeGh07VGp
         9LLEDFpiGNSA5YZZAMLAKiUSS5Rrbc9gGjL5FfV7KCoShFwQrxwzZOlV3DV+Uw6u2CYX
         4Nj1vf6iB5kGXp5b0OR81SNOhwl80v6rbmS+KCs829NQyjDHP4wkoA4UngDuaa8B4iLv
         eZ4tc0JC4DmWXUeO/40G1XN0SkZoSHw71Xp+5ftC9UuxcrAWSDSQ4GTCm2QAOOZyf08D
         NTdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uAdivLrGs64yf+hN3Bq98ZBtqSsxp11GzfmYDo4jUoo=;
        b=uo6oHT8GX0jY1/Y9mmLLHMypU/g0iAnNjaAFXzBA6Pmw2dk3PydotVxK4ItHBqM+qm
         T39udwu1Pa75lS38QaptaBZmVZ1Ni2jNvGuQXwlfYSblf1XGS/zrvKDBzH9b5UDBOuS/
         GvgkVj6jV5StI0rvCM1NBc1cUF7RoVyYoshMfEzwuM70MUK0xRuDu3MkU/HuHVrQf9kV
         sZEwUCkFmQmG9WtfK4T3LDf60Kr1MeBq89FuGd1TAl4YL7SUQK/OVuA6RC9JuZgtsDJN
         LWK9YJHRtsDGLcSp8ZBv4U1uD/EXCOHQAiXItDe73Flba3tD4nIrtnvTSFY71b3aUOL4
         413g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@garyguo.net header.s=selector1 header.b=Mn6Y2KeC;
       arc=pass (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass fromdomain=garyguo.net);
       spf=pass (google.com: domain of gary@garyguo.net designates 40.107.11.133 as permitted sender) smtp.mailfrom=gary@garyguo.net
Received: from GBR01-CWL-obe.outbound.protection.outlook.com (mail-eopbgr110133.outbound.protection.outlook.com. [40.107.11.133])
        by gmr-mx.google.com with ESMTPS id i21si20058lfv.2.2021.10.07.14.42.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Oct 2021 14:42:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of gary@garyguo.net designates 40.107.11.133 as permitted sender) client-ip=40.107.11.133;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=LeQxm2ySKWNtVJUdzaxU/F8+gTNCM/fMi+XOXMJIl3aSn8njPaPYBiKvTYUp1vNsmj30791e+/qCfl/BK8Gwz3psETd+GT6Z8zi+AQTwmE1grjm3FutFG/XzTa2e+Qma+LLhZYvxyo3vQ93YDoWhYV/8m8HobN37+MEEO+vpElIPfParoo519CkRdepcaAHZ+LaTFp5p1ec14bYv3Cetse0d6ZhqOiPJQ8fYukfhiZJaWyEYzxxaUsglE3Ffa7G4xCvD0XMXbp3QBqvEuHnY0Z8bmt0KbWzznZMyjqxXJrQaNlA/5LpNmBxoQmzs2yevWHraRUppDZc3Pd89TPDZ/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=uAdivLrGs64yf+hN3Bq98ZBtqSsxp11GzfmYDo4jUoo=;
 b=JbypDqWvbOtXk9OR7i02eGL/tUZjyGuuYD0eheRUCvdbklmXgIMF8kSRrZ+rnp5DbnpJujBcOFJf4fcucQRW/wIXcHxfYySXz1XXZoTM02ITCjkgFWEsoGP64eiThQbuvJRVoEmqDKBLIexJTXgBXAO3+8dNLWnKPkMt6ZwHdBJaJLvI/c9Ah0wVMdKXCXOdNCZT7/BUedwo0pHB5IYDkHNYzz6t79XA8jaMEj2UVH+1B/2x+KW08XPY3raK8qq/2tQUfP6rrce2SeqZ0BO1tr+R3pxuy9xFtdVU+6Wt6GqTsupjjU2cuUvSuF/RQTx0kNzZLbN7AR1e6jFN4kgn0w==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=garyguo.net; dmarc=pass action=none header.from=garyguo.net;
 dkim=pass header.d=garyguo.net; arc=none
Received: from LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:253::10)
 by LO2P265MB4303.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:200::6) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4587.19; Thu, 7 Oct
 2021 21:42:49 +0000
Received: from LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
 ([fe80::35d4:eb8e:ecdc:cc89]) by LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
 ([fe80::35d4:eb8e:ecdc:cc89%5]) with mapi id 15.20.4587.020; Thu, 7 Oct 2021
 21:42:49 +0000
Date: Thu, 7 Oct 2021 22:42:47 +0100
From: Gary Guo <gary@garyguo.net>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Marco Elver
 <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev
 <kasan-dev@googlegroups.com>, rust-for-linux
 <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211007224247.000073c5@garyguo.net>
In-Reply-To: <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
	<YV8A5iQczHApZlD6@boqun-archlinux>
	<CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
	<CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
	<20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; i686-w64-mingw32)
Content-Type: text/plain; charset="UTF-8"
X-ClientProxiedBy: LO2P265CA0397.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:f::25) To LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
 (2603:10a6:600:253::10)
MIME-Version: 1.0
Received: from localhost (2001:470:6972:501:7558:fc3c:561c:bc74) by LO2P265CA0397.GBRP265.PROD.OUTLOOK.COM (2603:10a6:600:f::25) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.4566.16 via Frontend Transport; Thu, 7 Oct 2021 21:42:49 +0000
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: efd7a9fc-7317-4001-7b60-08d989db6878
X-MS-TrafficTypeDiagnostic: LO2P265MB4303:
X-Microsoft-Antispam-PRVS: <LO2P265MB4303EE520826FF56D7847B66D6B19@LO2P265MB4303.GBRP265.PROD.OUTLOOK.COM>
X-MS-Oob-TLC-OOBClassifiers: OLM:9508;
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: bAc9XhbHDkuso9RNcK0eNurL17X7P4oO8IXwE3h+fAEYCtJ8AW2K3Lv3Q+8NjZsSIkiFUm5sfPjn+FnPDiEz7Uj2HsRviZwadatoUIAmmGKhjyn/dKRMBTgZZzPYXwRdJHlY7tGnEdrfy3VXoi21q/lCN7g1K/zewp6MUb9/7JLyBZaOAD/HjF2rhjlv9iJgF0PmFMvQtfbsPPPe0qLfLKh1XE+nut48Ot6xOAIBoDlcNOJTO43uqXCXGd8GTM20swU93DiLUWqEcF92GgjgD1GHNy9nUADTLci6m7LnsVUg4PV/rTffjZnQ3U0+siiL2XDFCMrNVrKLECj9ueo3CKDDTF02y5pwCB18ma4Vxv7mnEyZ2scvtKcuQCKuvlpYi5zOYnx5xaEGKN6TcGeiwuaomCLsye1uCfizQ7g1FVy+b1TOgdYeLYxZbWCGyS+o5ln0jFSDnZCwkrzLm7H1XSCDudzAz54TnkvBb5g80Y/laONLqU5fZDsbwW93ejp7Laol0sxQ6FBm0mR4hV5O0Ofd458PYGUoKw/qUCTU2KVLmTrHAEYIBAns84+TP9Sgz3tGmJhXUmuuSvUCgfX9AvnyxhBd9dR5Qgb62boibvVXMWjdtOK4FGCSrOFMvdGUgGHYj3R+MsFQzCd8dg5ciYlsv7sR16AH9jA156f046C9KCW/8Gj1GUlDNrOpiLsJi8yz/Sd9Ys9VhmYqA5FJJg==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(39830400003)(136003)(396003)(376002)(346002)(366004)(2616005)(83380400001)(2906002)(1076003)(6916009)(186003)(66556008)(66476007)(66946007)(6486002)(86362001)(36756003)(5660300002)(4326008)(54906003)(8936002)(316002)(52116002)(6496006)(8676002)(966005)(508600001)(38100700002);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?us-ascii?Q?uVSjc14oHQ7ywUTyfsLfxDjuQzkkmMcEVecCaUxp6ZmslGluKDEYyza3tK8Z?=
 =?us-ascii?Q?LEqDOSitffHAgEp/98sC7eQZcjl3a1jJ5cgxvIXYAP+Viu7PcFa461pyvain?=
 =?us-ascii?Q?wJfs2g9j7auhT5+mcFNlj6TE/ZDPM7WXFAoVqS6Ulh0Pvp8247EbWoIiNJSJ?=
 =?us-ascii?Q?EqrOCJwFkWYbmEsI1n1mtM5Frp6kcmgJt8H0WC8pUvR1jSeCuK3Tp9zTtpnb?=
 =?us-ascii?Q?8MkYP5M2iiKwC/YIgZ1wEBcRVG/GTgFxhaOSdHein1kAqD9H3tnSjM/i95Fh?=
 =?us-ascii?Q?d6GI5SdMY5EMzA/bmV6WxktweVaQrGlzB3Uj6kRLQxKvtzly6EHeuYRdaRRO?=
 =?us-ascii?Q?GgXD2aB91VdyJJMiMzYf+knzMVfubZXYH4/4aLp2JAByZNcvRxUC3lpVtVlh?=
 =?us-ascii?Q?s6L9MPz4QnG0CfFzgChVnHyRs+tG7/01p2BJK8iSBmHmIdqkXoxsdXuaUfWU?=
 =?us-ascii?Q?g76wDqRV2FWejiVHIafmF0qXyIZqrKG6yVMZn3/v/Ol0wi9fdGM9aOU5ZYpd?=
 =?us-ascii?Q?+9pVrp8Eicb5G6gSELqqhM6/TZP0Wnv3gKVHuf6Vl1sej/Facbs0H5kO8GY4?=
 =?us-ascii?Q?GcstyLRYSPONPuEq43OOqssxxJlPuTg7YCLlO0ZQTBoPfzLmM/iLbZ2bJC8l?=
 =?us-ascii?Q?J898Cuf2GOZDtnsTirGFDyauR8vLDkHZ0i4WCdG9ITD+6JdxNgoFu7tPElWm?=
 =?us-ascii?Q?jXmE8PAlp4cau7uk5cFbvWD6U5ZrAURtJQnGF46UkiJRqXANtwnme1peYenV?=
 =?us-ascii?Q?SBzUZyJYa5KY63rXmjjwZcdpv/D54NTrnG8mar1CuioYlRBrr1Nh0C7jg23a?=
 =?us-ascii?Q?d0r+xLC5ytGp9QUGliXMa32UTsZ9TR9KgppMPdW1nvyUB4PrbfUKpgbYlae0?=
 =?us-ascii?Q?XFhShJ+KWedg4WnYIdYm1e4tEU5/aT3shLcp5IraWMIYWyStVlKBE/FlU61r?=
 =?us-ascii?Q?bv5CxuYDqNdNaRzziCubWi9fVFRINuM6cF2oeXwtr7HEClWsgrc/7XWgVumh?=
 =?us-ascii?Q?EXzyR3sJjjjKQhOPOxxsUiAcSWpBEbDIYE4VE4YD6CCOMS/H84lK1TLgzmor?=
 =?us-ascii?Q?HpPsDRHlfXkH4c5l+9gkVvwDYPwC010JWFvpsYndjZNt8EBCI3Z3MeIPEHxI?=
 =?us-ascii?Q?1PRY7STLRSYl+NZ5LYZVoMcLjTEtKWVCR8OMKyF4s1FaDfgqjCp/HkBAB7A0?=
 =?us-ascii?Q?/S3pR6evqJYiGvuh6lablHcCJOqIPqwoTlmritOPLyZlWc5DyYeuQhnv3aye?=
 =?us-ascii?Q?1hHQD5g0/+pyrBjwiiX5nViutWRxrc1iUlvOQ7sfzaFzfQXZ6H2VfPq+A6cu?=
 =?us-ascii?Q?ASXaiyLDzkGxE+KfhE/yuMhI9Hp7MYJxzdB9D7uiNQOmeUuAJV1lqs1HA4mC?=
 =?us-ascii?Q?B1SBWEQBQczkZnjrDvGxr429T0Nj?=
X-OriginatorOrg: garyguo.net
X-MS-Exchange-CrossTenant-Network-Message-Id: efd7a9fc-7317-4001-7b60-08d989db6878
X-MS-Exchange-CrossTenant-AuthSource: LO2P265MB5183.GBRP265.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 07 Oct 2021 21:42:49.7904
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: bbc898ad-b10f-4e10-8552-d9377b823d45
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: TSqDVLwZCMqlq/WHvFHlpYiJ50QTPS0wMD3pk1lhqLouqLAFfeR1kAsdPgQ2g8z0txsFARXXUH/NPqnVD6fNrg==
X-MS-Exchange-Transport-CrossTenantHeadersStamped: LO2P265MB4303
X-Original-Sender: gary@garyguo.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@garyguo.net header.s=selector1 header.b=Mn6Y2KeC;       arc=pass
 (i=1 spf=pass spfdomain=garyguo.net dkim=pass dkdomain=garyguo.net dmarc=pass
 fromdomain=garyguo.net);       spf=pass (google.com: domain of
 gary@garyguo.net designates 40.107.11.133 as permitted sender) smtp.mailfrom=gary@garyguo.net
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

On Thu, 7 Oct 2021 11:50:29 -0700
"Paul E. McKenney" <paulmck@kernel.org> wrote:

> I have updated https://paulmck.livejournal.com/64970.html accordingly
> (and hopefully correctly), so thank you both!

The page writes:
> ... and furthermore safe code can violate unsafe code's assumptions as
> long as it is in the same module. For all I know, this last caveat
> might also apply to unsafe code in other modules for kernels built
> with link-time optimizations (LTO) enabled.

This is incorrect.

The statement "safe code can violate unsafe code's assumptions as long
as it is in the same module" is true, but the "module" here means [Rust
module](https://doc.rust-lang.org/reference/items/modules.html) not
kernel module. Module is the encapsulation boundary in Rust, so code
can access things defined in the same module without visibility checks.

So take this file binding as an example,

	struct File {
	    ptr: *mut bindings::file,
	}

	impl File {
	    pub fn pos(&self) -> u64 {
	        unsafe { (*self.ptr).f_pos as u64 }
	    }
	}

The unsafe code assume ptr is valid. The default visibility is private,
so code in other modules cannot modify ptr directly. But within the
same module file.ptr can be accessed, so code within the same module
can use an invalid ptr and invalidate assumption.

This is purely syntactical, and have nothing to do with code generation
and LTO.

And this caveat could be easily be mitigated. In Rust-for-linux, these
structs have type invariant comments, and we require a comment
asserting that the invariant is upheld whenever these types are
modified or created directly with struct expression.

- Gary

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211007224247.000073c5%40garyguo.net.
