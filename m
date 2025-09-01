Return-Path: <kasan-dev+bncBCD6ROMWZ4CBB2HG2XCQMGQEQT6PZRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id C510BB3DFF6
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 12:20:26 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b3118ab93asf53885351cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 03:20:26 -0700 (PDT)
ARC-Seal: i=4; a=rsa-sha256; t=1756722025; cv=pass;
        d=google.com; s=arc-20240605;
        b=jmview25c1hg11MGjIMHagOL+SuMe8Y0quKIrguP+BRBuJLhgMhDRbL4+3FOr+sZfH
         ZYwLOn1QAyny5r+fInDDkWwU8T+LGlzD5ti81nRC7nE66G7fEda2VG27J7O0eHw8g2nC
         W8J+ULEEqUkoZ+ELX/Lkzta7nuKzoJ6bmfrGSBbjZDxrgHzrIXlptnPIfJigCVbc4goF
         CYEbioMBRuvVFMDe4edgEF8XR5pUs/ZtQeVAV5hYTA5DUKWJcQhOx2b+7Nfe1I7GSzP/
         aByu6gS4CvSHYYjrzJ28EV3KFzw0NtJywoUyAnhhcY/FWZsxdZi/VgFOyS/uvDR2CrYZ
         MYiA==
ARC-Message-Signature: i=4; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:nodisclaimer:mime-version
         :in-reply-to:content-transfer-encoding:content-disposition
         :references:message-id:subject:cc:to:from:date
         :authentication-results-original:sender:dkim-signature;
        bh=odJBwdg2JgyVp9IahzWwZrVb6CJrV7gOCqJu5/LLzhg=;
        fh=bfbkX13kb8CKG+5L9V/wehJl6/au+JdJKqRq1uvewZI=;
        b=Yt+xAiuGFcMcQjUQG7sO6DBEatR9N6hzPD/TZdNeJSdmcnxilEI9JL/0yPKtuJkecD
         vxmK/l/iZy6hZOgGVAetHp2WyYNsiOOf7P/I6kkm65dgonF0kP/jhrv6U0TV6BaSln5w
         XINz0ya1e/SjaAecxRleFqJZtqv+wMdub1F+7wMyFxKdEjf6RewgalycO65AuiyGALwR
         /wTGtNxbTejF0KsvgU1joXcpoRyC9/1VwLlYBie4O1pQOCoPfukhl3J+1PI1t5hX39de
         FWCoiCQewvI6ONYpGRGoJJdwFtRIpAn+tDQ/WDVvo2CG1hU7YyO5BoG8y86iVXkc8t9k
         JrbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=4; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b="HFrpc/1/";
       dkim=pass header.i=@arm.com header.s=selector1 header.b="HFrpc/1/";
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756722025; x=1757326825; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:nodisclaimer:mime-version:in-reply-to
         :content-transfer-encoding:content-disposition:references:message-id
         :subject:cc:to:from:date:authentication-results-original:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=odJBwdg2JgyVp9IahzWwZrVb6CJrV7gOCqJu5/LLzhg=;
        b=sATZ68u2uXS2PWI0EJAcsbEsiiqXOWLQ1VPbeneElKECigAGeNegJ4t3neW9EOnGo4
         zRhdV+yj5uWzNMq2ze0uevBx796qS3/LutjY1OnkAm0d83IWPNdKcXEFziXLalWowVzT
         fmdINHpak7j/htYy3kLPSoRlECHaY6sZCepgUocWBub+nW9/dPB/Xg1k4gwq1LvqIXCi
         jYSBGPPCQzBCBsvLQknnOdOHQ23OsaQO1pzeqnwDIx7FTX1M6yjkgCB4IvBSUvlqFfbG
         d22VDvdX1vGIs+mA2gJJPf2yt4EAO+EYsD1i/cKNXYNvvGRa8enJxPWjzxyF0NvKtAki
         y2rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756722025; x=1757326825;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:nodisclaimer
         :mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=odJBwdg2JgyVp9IahzWwZrVb6CJrV7gOCqJu5/LLzhg=;
        b=NGSasCPRVOQSjf5k/MH1dAZJOH/2kpY+riv1Qm2hJQqhE8mgvd4QmmTNPaO87vr/IK
         kzFCQiUs49UxM2qHJ7IYUiWdtrdsx7QKtvwr/haAL/s4+W9FEwDD3ENGrO1vrqX+nv/0
         aXS5O65VuE7b9Cwiz/z5cjxO3JYRUE/OSBiaBbUvQ0OEwvuc+/HS1C4/NKs8AqM35WNH
         VLo2pUKrkd8A1XeQYU8jFG9G+50mm2tz6DokWI1ctMvNMc1PKMJCxoOrQDdENzwLwUY0
         boQDY6jGesN9tisiZPcUNrw8kaUXPQn9DDibuu1DpOYdZcUC7TyRbYS44UcmBcpT8EbU
         K8Tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=4; AJvYcCXknUBx/CdE7vRFAbpswzgmBHfl19KQCpG9EV0pBg4T90nVOONLe74YZiMugUy+cT7IJ5141A==@lfdr.de
X-Gm-Message-State: AOJu0YziMr1u1Yu6X1DU0Llht+Kx9ke1nkbADQNEa1uAi/YDDtdFr7ix
	AoHJmQbPUX9FyE9jM8KqaASf4YKRnIkN/B5QpOX9AYNXjS9ovULNqMk6
X-Google-Smtp-Source: AGHT+IGHux6RrRoz1nedTLnc+o0oTAMMiPYBogYxkCuIfD2Yu0ypa0ncTfW/gDmlh52Ny3Fvmx5zaw==
X-Received: by 2002:a05:622a:296:b0:4b3:10f0:15d8 with SMTP id d75a77b69052e-4b31dd27112mr80666881cf.81.1756722025044;
        Mon, 01 Sep 2025 03:20:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdli6oGppDjlRQQoPQDx9smcFFpackplq4aGMqNc2k8Ew==
Received: by 2002:ac8:5741:0:b0:4b0:889b:5698 with SMTP id d75a77b69052e-4b2fe667756ls66554931cf.0.-pod-prod-03-us;
 Mon, 01 Sep 2025 03:20:24 -0700 (PDT)
X-Forwarded-Encrypted: i=4; AJvYcCWi2YO/AJC6aFEx+/z+xQg4foV3MbgZdp+dOgMGDhDKnc5b9kQ8tql+E7/2dLKd3cVrcCKF03ZTU7g=@googlegroups.com
X-Received: by 2002:ac8:5d4e:0:b0:4b2:f56b:9e0 with SMTP id d75a77b69052e-4b31d844988mr72287841cf.3.1756722024030;
        Mon, 01 Sep 2025 03:20:24 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1756722024; cv=pass;
        d=google.com; s=arc-20240605;
        b=MO3ByWsiIc/FG3i3+0HX5qPClyR7iXD/xIfgscn+zqIZcpnbGOp/v1kbLS0TTEU+l9
         rtOGuQbcxniwYBkNkHdLO85lGsjdmoiLnAc8zWLuw0V0QqeeTcbigoe/A2/Y3hQ8iQ6a
         A/ozzp+vhogKMoFKvp9h6FtSiCwG4cfvDJR65FMUdQVk//mw1VcB0uLXXm+wqvQBHAEj
         ANAX9SKF8eZzQbPpOm80ky1/q85wxSt0Rw4Da+hSBqhLVRC5Gp7LU6mR/rgNYI9r49jD
         xaCmWsBxQj6Qmyqb6rRx4ysNXJfmYP4M4KHd6SMPLXf2KTLnwK6nPri9Qq+f95QtyP02
         +maA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=nodisclaimer:mime-version:in-reply-to:content-transfer-encoding
         :content-disposition:references:message-id:subject:cc:to:from:date
         :authentication-results-original:dkim-signature:dkim-signature;
        bh=qlBpAeZweiASUJTC+nVkYA4THNAa/rAJ7AAp27RPTyw=;
        fh=ufqDvzVfba2dkpl8jTip/BMio/P94U1NAsuX93cABCQ=;
        b=aZITGMYfddFPaiWWcEFij1k9w4pyuXw2LGY82nmytbBo3ZSCZspj/L6rMuUzhgT2UB
         vT7+mTo2Wj6DNzJ2I77nGzJkNpAVGPutNntsxuDZgRdp124CmqgK7/aIbclZ2xS2NIpR
         hxgKtyuutJUdzw9mmmPdT/NeBuQR2JF376wiMD+VJ48rlBuRK+sGm+pZn1wrAG3OeKkb
         0nn9SIJZ+HhZyNtx44KR2Ecwk3y4QhEieURBTr4aWows1Hq4CSqQHK38Iu2PdXhB3ajt
         +pdlvYWV2yrEg+42WqhEAoxl1mmgC8Uz9hiIo9ih4k4x+unahd6WtoW2hnvvH+i0tSoL
         c+tA==;
        dara=google.com
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@arm.com header.s=selector1 header.b="HFrpc/1/";
       dkim=pass header.i=@arm.com header.s=selector1 header.b="HFrpc/1/";
       arc=pass (i=2 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass fromdomain=arm.com);
       spf=pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::3 as permitted sender) smtp.mailfrom=YeoReum.Yun@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from DU2PR03CU002.outbound.protection.outlook.com (mail-northeuropeazlp170110003.outbound.protection.outlook.com. [2a01:111:f403:c200::3])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b30b3e0756si3599871cf.0.2025.09.01.03.20.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 03:20:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of yeoreum.yun@arm.com designates 2a01:111:f403:c200::3 as permitted sender) client-ip=2a01:111:f403:c200::3;
ARC-Seal: i=2; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=pass;
 b=lyJ3wybiiboSNRNSUWR/HM/wECtMITRmIkU1K2kXLohCEP4F9KK/ArfSlUk+fBv2/c4ffbtvZJQSzjTPi2D4DL5xfDzpNg0o8NfvTqpcy2/I+a+yXUtawwPMgC2960JS31GvRWMvXvLzFGUhQu9FflsrGMFMSDTv0kdhkcahDf+Mn9zjBV5CHEb4yL/fr9q135LOfTSDw2ldUOGziTB2m92KNUPAIuGnv0g0JWSCkgcoPPOv2FPA1gcf7ItOBcbaLzwkZWA9BYsrid3ZA2AH+Hm8BNV22MdZ90/teF94EN1qChzAkOTgbdypP9k2sSa29pdYAmrBTdCN398/se9gyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qlBpAeZweiASUJTC+nVkYA4THNAa/rAJ7AAp27RPTyw=;
 b=YQSiN79S+LWFg2UikHrzKzKkU1NYe4iYMaxffIlGXw7L1M86E7SUSpekN5vVgtDluh4J/JzcAwZAzllpXNLt0ch0F/bT/3C75CIGtzlgPfKfuPiQmQVyFO7ncDgYeRPc+6D+q247cQWFUadlgqFJ9HfDt4eRm+Cgxn6/o/2qbpXvSIeoTQNfdKXa131g8Rd1h95PZXwqIGwRgV3FPREfDdiIMdmpallw2fR5UgvAQ1/R8R7HnjLWifxJ6G+wsftRDxDly1nsrWKrwkn27mIq0nNTX4JoAymRaXy965KyNTEMvS2dBV7pyNiggRzksSa7S1faPG4fePhtegmBdDe0aQ==
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 4.158.2.129) smtp.rcpttodomain=gmail.com smtp.mailfrom=arm.com; dmarc=pass
 (p=none sp=none pct=100) action=none header.from=arm.com; dkim=pass
 (signature was verified) header.d=arm.com; arc=pass (0 oda=1 ltdi=1
 spf=[1,1,smtp.mailfrom=arm.com] dkim=[1,1,header.d=arm.com]
 dmarc=[1,1,header.from=arm.com])
Received: from AS4P189CA0023.EURP189.PROD.OUTLOOK.COM (2603:10a6:20b:5db::11)
 by DB3PR08MB8962.eurprd08.prod.outlook.com (2603:10a6:10:43f::15) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9031.24; Mon, 1 Sep
 2025 10:20:11 +0000
Received: from AMS0EPF00000198.eurprd05.prod.outlook.com
 (2603:10a6:20b:5db:cafe::2b) by AS4P189CA0023.outlook.office365.com
 (2603:10a6:20b:5db::11) with Microsoft SMTP Server (version=TLS1_3,
 cipher=TLS_AES_256_GCM_SHA384) id 15.20.9073.26 via Frontend Transport; Mon,
 1 Sep 2025 10:20:11 +0000
X-MS-Exchange-Authentication-Results: spf=pass (sender IP is 4.158.2.129)
 smtp.mailfrom=arm.com; dkim=pass (signature was verified)
 header.d=arm.com;dmarc=pass action=none header.from=arm.com;
Received-SPF: Pass (protection.outlook.com: domain of arm.com designates
 4.158.2.129 as permitted sender) receiver=protection.outlook.com;
 client-ip=4.158.2.129; helo=outbound-uk1.az.dlp.m.darktrace.com; pr=C
Received: from outbound-uk1.az.dlp.m.darktrace.com (4.158.2.129) by
 AMS0EPF00000198.mail.protection.outlook.com (10.167.16.244) with Microsoft
 SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9094.14
 via Frontend Transport; Mon, 1 Sep 2025 10:20:11 +0000
ARC-Seal: i=1; a=rsa-sha256; s=arcselector10001; d=microsoft.com; cv=none;
 b=Usartn+LSGkOMuKrx7LQRPXdeWrwXxgQEdN2Mpxg/+UwWcIiGhlT1haEhIy3FCylS/TyORkAS5C1a1aQGIBLvOwe+5aSFcggmQ/gzXb7/A71uDGcbibd3io0c8dNN+jwWQXBBtC7kpis+RqIoNF4KK0jVMlIi4JddG3ESQWxV5JSkYIjJh0EjUY2rG0mFBP1+En+vecTbaAlW4n5PiOmUJmmC4Ae2gUhNvyqpZJD98eRoDjJi+Tcm8hUZtrWWtr3yswJUPJBtRaGivKs4XjkCs0CDWYdh1YJZn9c7twxvNTeuOzb8HM7fjibZedRt4vN3Qp5rLMZqo0FkU7YblzLug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector10001;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=qlBpAeZweiASUJTC+nVkYA4THNAa/rAJ7AAp27RPTyw=;
 b=Ioj2z2lPuBHviqF8hkZXcU+jokbqe6ECp+2ayUWfu9uw4J3x27o0H8WFkquScIzZZaYdpdh8PY8rtQRwXxCAp8NYNT/G1LnGxqAszSJGcvTKgxUZnTDj0NrNn2sVIGCYyfXUd9ozLMJXIDMIAcbAtbcPqXrNvp2eWrfhxMbVGhbneYWkJN1xAc2EavBKT7gutdb+FsHm2zL+hvlz4kgI/dyZQKgKLKfIDPwMyOtb0GSmIOnbc1vpTRFcvBQJeS3EZPyOFuDqZCJ5ukiAHaIVEzrzDJZHuBKBnGlkFTIZtdklMrZ06Buxif9P7K7EVa377VWHXG1bchwV+WWWkx8EWg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=arm.com; dmarc=pass action=none header.from=arm.com; dkim=pass
 header.d=arm.com; arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=arm.com;
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20) by AS8PR08MB6327.eurprd08.prod.outlook.com
 (2603:10a6:20b:31a::11) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9073.27; Mon, 1 Sep
 2025 10:19:38 +0000
Received: from GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739]) by GV1PR08MB10521.eurprd08.prod.outlook.com
 ([fe80::d430:4ef9:b30b:c739%7]) with mapi id 15.20.9073.021; Mon, 1 Sep 2025
 10:19:38 +0000
Date: Mon, 1 Sep 2025 11:19:34 +0100
From: Yeoreum Yun <yeoreum.yun@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com,
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com,
	will@kernel.org, akpm@linux-foundation.org,
	scott@os.amperecomputing.com, jhubbard@nvidia.com,
	pankaj.gupta@amd.com, leitao@debian.org, kaleshsingh@google.com,
	maz@kernel.org, broonie@kernel.org, oliver.upton@linux.dev,
	james.morse@arm.com, ardb@kernel.org,
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com,
	workflows@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v5 2/2] kasan: apply write-only mode in kasan kunit
 testcases
Message-ID: <aLVzNmN+G/usuJoE@e129823.arm.com>
References: <20250820071243.1567338-1-yeoreum.yun@arm.com>
 <20250820071243.1567338-3-yeoreum.yun@arm.com>
 <CA+fCnZcAgW1iVKJ-MyzzdFoaDpRpA+CnTt2y22uZcUbSegc8CQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcAgW1iVKJ-MyzzdFoaDpRpA+CnTt2y22uZcUbSegc8CQ@mail.gmail.com>
X-ClientProxiedBy: LO4P123CA0251.GBRP123.PROD.OUTLOOK.COM
 (2603:10a6:600:1a7::22) To GV1PR08MB10521.eurprd08.prod.outlook.com
 (2603:10a6:150:163::20)
MIME-Version: 1.0
X-MS-TrafficTypeDiagnostic: GV1PR08MB10521:EE_|AS8PR08MB6327:EE_|AMS0EPF00000198:EE_|DB3PR08MB8962:EE_
X-MS-Office365-Filtering-Correlation-Id: 6db5ad70-9ab6-4d72-bf47-08dde9412259
x-checkrecipientrouted: true
NoDisclaimer: true
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam-Untrusted: BCL:0;ARA:13230040|1800799024|366016|376014|7416014;
X-Microsoft-Antispam-Message-Info-Original: =?utf-8?B?dVNMcUxYamdKNHFZZzRuTlBOSklJUy9LdUJoQTFFcVNjZ2k0RGxqOUhyUFBk?=
 =?utf-8?B?eERhOHEyOWVZMEFCOXAwU3QvV3ZvdHdsekxFRWdCRHBhTXVJa0F2ZlpFWVZI?=
 =?utf-8?B?eXZJczRYMW5YaWVmRGZReDhsc3M2WkM5MWEwa1dJM3RuZFh3aHpXVFBLbDJR?=
 =?utf-8?B?QVEzLzRxVURIVGwvZGZ3ejJiamk3clBkSWVCNkg2L3pTamdETzNlR1AxSHlt?=
 =?utf-8?B?OEUrWmtXYmkyR24wMDRxMTFaRDk1TjdqRWZReGpSODY0YWNDSTZ2LzkzaWZX?=
 =?utf-8?B?TFJwbWlSUWtuSElVam12NE1sTzhqOXRDZk15QjA0Y2FLWGVkcnpqMGxiYTJG?=
 =?utf-8?B?TUFwdWVOWWxIQno2TUVIYVJpanQxUFhXYWZUMzFzTkZMSkpOTy9JUzZkVUkz?=
 =?utf-8?B?bmtwSDhLcjU2bXVKZGFLWGppdWJ3NFBhREs2bVNPYWVDY1YxZkcrNUlYNG5G?=
 =?utf-8?B?ZnduV3lUYmQwQ2hTd3NOZ2liUXFSeTNPN0JlcXZvY1BROEVZdlhBVUhJVVdD?=
 =?utf-8?B?aDVtTWhJVlNkL05LNWUxams2Z0ZLcVo3dFJZL2F5M0xVOWFSV2swbDVwQVJv?=
 =?utf-8?B?TFJRcHlaZ1hjM2h5VHhDQTZBbXJTSHRZWGs4WkFTOFBxNVZMdGFQaFBNZWF6?=
 =?utf-8?B?TlB5cE01RkI3SjVjbXZDVVZhUzQ5blNnSjF6UTJVZkU1UXNkQjBNK1ltT0wy?=
 =?utf-8?B?WHFrREVvb1Nkbit4a3NDcmIwQjlrVEdjWmVMc1dnT3p2Wndxc3RFK1I5Kzh1?=
 =?utf-8?B?K01zSmpOUmpLVGNaZWY3TXRLM21QL2QrV29qSUFsbFNMUzJFYkY5Qmc5TEJF?=
 =?utf-8?B?NHlnN045TGlTRkJtLzJnbGU1NVlOOXBCbTB2VmNNMnBoY2RtVFE2dzFuZDRC?=
 =?utf-8?B?M1F6VWh5YmdwRUI2SWFxZXZmYkF3WGs4RVlnYXFxWUFaUGJ6SXdVUWY1Rk53?=
 =?utf-8?B?T2k0STcya0prYStzaXBybTE1dEN4RHJWTHhSUnhKVHRFNC9IQ2dGTEp0akFL?=
 =?utf-8?B?ek01WWt4ZC9tTnBvaGlHQjNNd045YWpsMTBEV2kxUWNMQ1pNd3RNUXhQN3p4?=
 =?utf-8?B?VDJ5aVBqYmJHQ1ErNUNrZC82L2ZzVDlETDZtdXVIQVdReXV2enIzU25CVVFV?=
 =?utf-8?B?LzdTeGUrdzJDSTM0RzFIbW8wK3RjRk5kUkl1UWhMclUrbzJYWnVIY3oyQkZ0?=
 =?utf-8?B?R05TZkxvWXRTUDhCdjBJTlVobWIwYUpGNzdRajhYSFVxTFRFSmk0NE95a1ds?=
 =?utf-8?B?cDErZ0w3Y3hUQUpnbDFDYXZEQW9KV0tQZ1dsVUdiZ0twazhPd3BuTzNqcmxh?=
 =?utf-8?B?UzloTmlVTmFHVDA4TGxyd0xycnlQL2lMeU11L2xOemJLL2pPRzQ0WlBYOEFH?=
 =?utf-8?B?dys5TEFrcUJYRnB6RTZlWG00YkYzZ0hoUTNNcHRUVnpUM09uY2xJUjZLYjM4?=
 =?utf-8?B?S09BSXdCQjM3enlaekdwSzl1R2E3YmdSU2ppOVpxQ0ZYdE1MVzhnM2VhK2Iy?=
 =?utf-8?B?ZXFETUNJU0JtTk9qV1NpWFA1MnFERDBWNkNROVdLWHdIQlNWQ1B3cVRCZlls?=
 =?utf-8?B?QU42Q3IvSFFXNVR3UDRPWU1DMVN6MUxsYy8yYzRhRmlmbTZ5Q3pIV1ZwYWhh?=
 =?utf-8?B?WEU3Tnp0WklZbndyaXRjVFlVdlpkNFZtUXdMNTYvRVlDamM1YU05NWtENjkz?=
 =?utf-8?B?K21HZVVPUGFUUi9EejBkelRBSUpGdWpXQ2V3ZTg3dXF3SzhlVWdRVGR6Nnpo?=
 =?utf-8?B?VW5nTGFvQlJjUTBLS3ErNHNtUk5rTURYQzM0N0Fpc3JHZ2JZM1JnUFZvclpi?=
 =?utf-8?B?cXRrUjc2Rzd0eWpLSTdrRER2bzJTa0J3Z2oyR3NUaWFqTmpmdzNPWnpmVm5a?=
 =?utf-8?B?Nnd2VTl6S3JRdmtvS1JpZlJlclhqOVJuT3JpK0FUdUlHWFFtR0NIbVlEbVZj?=
 =?utf-8?Q?3mxTegNhMMg=3D?=
X-Forefront-Antispam-Report-Untrusted: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:GV1PR08MB10521.eurprd08.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230040)(1800799024)(366016)(376014)(7416014);DIR:OUT;SFP:1101;
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AS8PR08MB6327
X-EOPAttributedMessage: 0
X-MS-Exchange-Transport-CrossTenantHeadersStripped: AMS0EPF00000198.eurprd05.prod.outlook.com
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id-Prvs: da397305-0530-4bdb-8bce-08dde9410e3f
X-Microsoft-Antispam: BCL:0;ARA:13230040|35042699022|36860700013|82310400026|1800799024|7416014|376014|14060799003;
X-Microsoft-Antispam-Message-Info: =?utf-8?B?Y0NIbHZVU2swbHhOL3RYNlpIbHdvVTF4bUhzRk9NMEJXZEo0MnFmNTFuNUlV?=
 =?utf-8?B?dTE3bmxBTW9xUEduMEhzVFpEVDhMeFliY0NYTDBrd0dlN3NoMC8xU1RuUHdZ?=
 =?utf-8?B?MnhRQ0hzWCsvZTFBcHN6OVdXZTVqakp6RVQ3RUdaK3JWdEFjUzhHOFVMMXk5?=
 =?utf-8?B?SGlkT3ZqOVR3RE5pdDFEcjNXc0FuNTBaS1ZGWU5FWlNybitadFNGdjdHZ0VS?=
 =?utf-8?B?RTl2bHVVcmdOb1doWmRxL0FydjRJdTZzYktUOUtYQlNWSHMreWgvTlFpOWJv?=
 =?utf-8?B?bkJEZ0xwTmlObE53T054aVh3QVpPRWZUanljYzdJY29qVHV0VnVBNG5HRytX?=
 =?utf-8?B?d0RScXNySFl5SnV5dW1sMEU3T1liZlRUcFBMckthaXllMzlpL0JUb29zNHdH?=
 =?utf-8?B?K1BNTm1YcUxuRUJpSEU1MWI1V25YRmdKK0loS08wNDNpSUpTK0tQcFJ5R0lH?=
 =?utf-8?B?c1BTeWJNaytqNzlsRmw5aGM3SFpUVE1WRGphaVZjbTJOVUdkanNVV2VTV29E?=
 =?utf-8?B?UUYvKytUVFpBTzhYZXB3T0lGbm1LemVhUDZMMUdnTHkxNmc1dlE1eHJXU0JB?=
 =?utf-8?B?eUZhZjJEejhjQnNmVCttQnM5bFZqUTVhYjJpVG1xejEwQjFqVGhWcXU2Q2hW?=
 =?utf-8?B?SVBueXFOSXYwckU2UmxNL1p6WDhvYkxLL1NJb1U5ZTRpSE44NXBJaGhZY3dV?=
 =?utf-8?B?TFZUeEpSU1hkQVhVUmlBTmdxbjFkUENpRlVlbHpqV3ByaktKSzJhMytWS3NQ?=
 =?utf-8?B?VVlwNHZ4UlBnajlhdkNTbUs4bklNSGNLajdsSW54RlM2NlZ1RGZZcEp1M1Fr?=
 =?utf-8?B?V0VzSkFueExDSnJrRm1oN0pMQmdjWklOeGhlTllnc1NzZ1BudXU5RWJOMkRi?=
 =?utf-8?B?U0JRcmpINUtoSzNnOVd4dUwyY08zWUpIL2c2djdqQnZTRUlLVWFmeStsWTNY?=
 =?utf-8?B?TEtFRzRiZi9XZ0VDUDVJUjhGMzZXNjlseFp4YTdlMm5FZXRCclNSY08rY1lG?=
 =?utf-8?B?c2NSZ3k5Z05saGZ2eGd4cUo1WHRWcUYrRGhuK1VMUWszUXh1QVo4VWtkWkJ1?=
 =?utf-8?B?TmFDcHRjQkNMVlgxb2dVdUxaZ0RDdGtSZyt0dHFwZCttaHFhTTRwM2o4V2NX?=
 =?utf-8?B?VW5PZWMrWWVOWVhoelhDakUzUi9hSUpyVHFzS0doWGI5TS9lTHM1YkxiUk9N?=
 =?utf-8?B?VlVXeG9qazViOHkzZklsbUp4RVlvL1kvMW41ekxyekpMZkhDays3VnpIdmxm?=
 =?utf-8?B?c3BLYUdFdU9JRmpYNDVjMms0NEZVK1drTXBBZUlyMWdROWE2QkVlUkx0YzRP?=
 =?utf-8?B?blNtMU10SS9Zd043VHZGcVRteDRiVkxiS0lxc2JqVXE0SDRISGEvY2Z0ak9M?=
 =?utf-8?B?dXlVRG5DRFk4UTVFQW1aYjFhQVJYVXRJT0FlRmFGVlRTQzNHZ25xTXFuQnVC?=
 =?utf-8?B?TEh4ellsbE8wNFFIU3kxb0x5d2pJcjlzcW1FVUFXMUUzeGlSNDllMytqbEVN?=
 =?utf-8?B?RURVSWs4WDFMTWVsckd6T21GVHhOd0IyV2tUSU9CT29OTVBtQ1kxK0FZT0Q5?=
 =?utf-8?B?ditFTGRRS0Y3aFpTMXRRYjd1VXgvK2NkT2t6clZYRGFWSEVBQ0JDRmdTcVpp?=
 =?utf-8?B?bWZGZm15S3lOOU04elJNZUdheVVhazUrR1NVV1VUU2ZicXRuQkFQVHVTQTdR?=
 =?utf-8?B?RC8vVEpmUHR4KzE3QVFUdHlwNTBaeUIzbUQ3U0JTT2VLV3prb2FBUHdrWk9S?=
 =?utf-8?B?cG1JT1NBZ2tId0MyaWxlUmZESjNJb0hacFNzeDVmSWFDaEh1ek80WjQ3Y09k?=
 =?utf-8?B?Y2NOVjlYMlFpZ2szQ29LZ3ZUOWV0R0t5T0VCWktTYUw0WFhyRFU4aER4MFhO?=
 =?utf-8?B?Y3R0SENPcjJ6bGJnd1dqbEI3c1I2eUQ1OTJrQUJjZHp6QjBvUllheTJPVUx5?=
 =?utf-8?B?WE9SdFdHYmZXUllINnlZNEs5WFQzVGw4d0ZURVB2ckNYMUQ3NllVUUh4S3JI?=
 =?utf-8?B?UnNoeDhRcTR1R3Rxd2VtZDNWbWRRS2Jrb3IvZGJpeUVrTTJPU1NtYUxPYk4z?=
 =?utf-8?Q?MEeyLk?=
X-Forefront-Antispam-Report: CIP:4.158.2.129;CTRY:GB;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:outbound-uk1.az.dlp.m.darktrace.com;PTR:InfoDomainNonexistent;CAT:NONE;SFS:(13230040)(35042699022)(36860700013)(82310400026)(1800799024)(7416014)(376014)(14060799003);DIR:OUT;SFP:1101;
X-OriginatorOrg: arm.com
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Sep 2025 10:20:11.3871
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 6db5ad70-9ab6-4d72-bf47-08dde9412259
X-MS-Exchange-CrossTenant-Id: f34e5979-57d9-4aaa-ad4d-b122a662184d
X-MS-Exchange-CrossTenant-OriginalAttributedTenantConnectingIp: TenantId=f34e5979-57d9-4aaa-ad4d-b122a662184d;Ip=[4.158.2.129];Helo=[outbound-uk1.az.dlp.m.darktrace.com]
X-MS-Exchange-CrossTenant-AuthSource: AMS0EPF00000198.eurprd05.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: HybridOnPrem
X-MS-Exchange-Transport-CrossTenantHeadersStamped: DB3PR08MB8962
X-Original-Sender: yeoreum.yun@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arm.com header.s=selector1 header.b="HFrpc/1/";       dkim=pass
 header.i=@arm.com header.s=selector1 header.b="HFrpc/1/";       arc=pass (i=2
 spf=pass spfdomain=arm.com dkim=pass dkdomain=arm.com dmarc=pass
 fromdomain=arm.com);       spf=pass (google.com: domain of
 yeoreum.yun@arm.com designates 2a01:111:f403:c200::3 as permitted sender)
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

Hi Andrey,

> On Wed, Aug 20, 2025 at 9:12=E2=80=AFAM Yeoreum Yun <yeoreum.yun@arm.com>=
 wrote:
> >
> > When KASAN is configured in write-only mode,
> > fetch/load operations do not trigger tag check faults.
> >
> > As a result, the outcome of some test cases may differ
> > compared to when KASAN is configured without write-only mode.
> >
> > Therefore, by modifying pre-exist testcases
> > check the write only makes tag check fault (TCF) where
> > writing is perform in "allocated memory" but tag is invalid
> > (i.e) redzone write in atomic_set() testcases.
> > Otherwise check the invalid fetch/read doesn't generate TCF.
> >
> > Also, skip some testcases affected by initial value
> > (i.e) atomic_cmpxchg() testcase maybe successd if
> > it passes valid atomic_t address and invalid oldaval address.
> > In this case, if invalid atomic_t doesn't have the same oldval,
> > it won't trigger write operation so the test will pass.
> >
> > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> > ---
> >  mm/kasan/kasan_test_c.c | 237 +++++++++++++++++++++++++++-------------
> >  1 file changed, 162 insertions(+), 75 deletions(-)
> >
> > diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> > index e0968acc03aa..cc0730aa18d1 100644
> > --- a/mm/kasan/kasan_test_c.c
> > +++ b/mm/kasan/kasan_test_c.c
> > @@ -94,11 +94,13 @@ static void kasan_test_exit(struct kunit *test)
> >  }
> >
> >  /**
> > - * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produc=
es a
> > - * KASAN report; causes a KUnit test failure otherwise.
> > + * _KUNIT_EXPECT_KASAN_TEMPLATE - check that the executed expression p=
roduces
>
> Let's name this macro "KUNIT_EXPECT_KASAN_RESULT" and the last argument "=
fail".
>
> > + * a KASAN report or not; a KUnit test failure when it's different fro=
m @produce.
>
> ..; causes a KUnit test failure when the result is different from @fail.

Thanks for your suggestion.
I'll apply with these!

> >   *
> >   * @test: Currently executing KUnit test.
> > - * @expression: Expression that must produce a KASAN report.
> > + * @expr: Expression produce a KASAN report or not.
>
> Expression to be tested.
>
> > + * @expr_str: Expression string
>

Okay.

> Expression to be tested encoded as a string.
>
> > + * @produce: expression should produce a KASAN report.
>
> @fail: Whether expression should produce a KASAN report.

I'll change with this :)

>
> >   *
> >   * For hardware tag-based KASAN, when a synchronous tag fault happens,=
 tag
> >   * checking is auto-disabled. When this happens, this test handler ree=
nables
> > @@ -110,25 +112,29 @@ static void kasan_test_exit(struct kunit *test)
> >   * Use READ/WRITE_ONCE() for the accesses and compiler barriers around=
 the
> >   * expression to prevent that.
> >   *
> > - * In between KUNIT_EXPECT_KASAN_FAIL checks, test_status.report_found=
 is kept
> > + * In between _KUNIT_EXPECT_KASAN_TEMPLATE checks, test_status.report_=
found is kept
> >   * as false. This allows detecting KASAN reports that happen outside o=
f the
> >   * checks by asserting !test_status.report_found at the start of
> > - * KUNIT_EXPECT_KASAN_FAIL and in kasan_test_exit.
> > + * _KUNIT_EXPECT_KASAN_TEMPLATE and in kasan_test_exit.
> >   */
> > -#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {                =
 \
> > +#define _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, expr_str, produce)   =
 \
> > +do {                                                                  =
 \
> >         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                        =
 \
> >             kasan_sync_fault_possible())                               =
 \
> >                 migrate_disable();                                     =
 \
> >         KUNIT_EXPECT_FALSE(test, READ_ONCE(test_status.report_found)); =
 \
> >         barrier();                                                     =
 \
> > -       expression;                                                    =
 \
> > +       expr;                                                          =
 \
> >         barrier();                                                     =
 \
> >         if (kasan_async_fault_possible())                              =
 \
> >                 kasan_force_async_fault();                             =
 \
> > -       if (!READ_ONCE(test_status.report_found)) {                    =
 \
> > -               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure " =
 \
> > -                               "expected in \"" #expression           =
 \
> > -                                "\", but none occurred");             =
 \
> > +       if (READ_ONCE(test_status.report_found) !=3D produce) {        =
   \
> > +               KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN %s "      =
 \
> > +                               "expected in \"" expr_str              =
 \
> > +                                "\", but %soccurred",                 =
 \
> > +                               (produce ? "failure" : "success"),     =
 \
> > +                               (test_status.report_found ?            =
 \
> > +                                "" : "none "));                       =
 \
>
> Let's keep the message as is for the case when a KASAN report is expected=
; i.e.:
>
> KASAN failure expected in X, but none occurred
>
> And for the case when KASAN report is not expected, let's do:
>
> KASAN failure not expected in X, but occurred

Thanks. I'll change as your suggestion :)

>
> >         }                                                              =
 \
> >         if (IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&                        =
 \
> >             kasan_sync_fault_possible()) {                             =
 \
> > @@ -141,6 +147,29 @@ static void kasan_test_exit(struct kunit *test)
> >         WRITE_ONCE(test_status.async_fault, false);                    =
 \
> >  } while (0)
> >
> > +/*
> > + * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produc=
es a
> > + * KASAN report; causes a KUnit test failure otherwise.
> > + *
> > + * @test: Currently executing KUnit test.
> > + * @expr: Expression produce a KASAN report.
>
> Expression that must produce a KASAN report.

Thanks.

>
> > + */
> > +#define KUNIT_EXPECT_KASAN_FAIL(test, expr)                    \
> > +       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr, true)
> > +
> > +/*
> > + * KUNIT_EXPECT_KASAN_FAIL_READ - check that the executed expression p=
roduces
> > + * a KASAN report for read access.
> > + * It causes a KUnit test failure. if KASAN report isn't produced for =
read access.
> > + * For write access, it cause a KUnit test failure if a KASAN report i=
s produced
>
> KUNIT_EXPECT_KASAN_FAIL_READ - check that the executed expression
> produces a KASAN report when the write-only mode is not enabled;
> causes a KUnit test failure otherwise.
>
> Note: At the moment, this macro does not check whether the produced
> KASAN report is a report about a bad read access. It is only intended
> for checking the write-only KASAN mode functionality without failing
> KASAN tests.
>
> > + *
> > + * @test: Currently executing KUnit test.
> > + * @expr: Expression doesn't produce a KASAN report.
>
> Expression that must only produce a KASAN report when the write-only
> mode is not enabled.

Thanks for your perfect suggsetion :)

>
> > + */
> > +#define KUNIT_EXPECT_KASAN_FAIL_READ(test, expr)                      =
 \
> > +       _KUNIT_EXPECT_KASAN_TEMPLATE(test, expr, #expr,                =
 \
> > +                       !kasan_write_only_enabled())                   =
 \
> > +
> >  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                 =
 \
> >         if (!IS_ENABLED(config))                                       =
 \
> >                 kunit_skip((test), "Test requires " #config "=3Dy");   =
   \
> > @@ -183,8 +212,8 @@ static void kmalloc_oob_right(struct kunit *test)
> >         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] =3D 'y');
> >
> >         /* Out-of-bounds access past the aligned kmalloc object. */
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D
> > -                                       ptr[size + KASAN_GRANULE_SIZE +=
 5]);
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =3D
> > +                       ptr[size + KASAN_GRANULE_SIZE + 5]);
> >
> >         kfree(ptr);
> >  }
> > @@ -198,7 +227,8 @@ static void kmalloc_oob_left(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >         OPTIMIZER_HIDE_VAR(ptr);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr =3D *(ptr - 1));
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr =3D *(ptr - 1));
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -211,7 +241,8 @@ static void kmalloc_node_oob_right(struct kunit *te=
st)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >         OPTIMIZER_HIDE_VAR(ptr);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =3D ptr[size]);
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -291,7 +322,7 @@ static void kmalloc_large_uaf(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >         kfree(ptr);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
> >  }
> >
> >  static void kmalloc_large_invalid_free(struct kunit *test)
> > @@ -323,7 +354,8 @@ static void page_alloc_oob_right(struct kunit *test=
)
> >         ptr =3D page_address(pages);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =3D ptr[size]);
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ptr[0] =3D ptr[size]);
> > +
> >         free_pages((unsigned long)ptr, order);
> >  }
> >
> > @@ -338,7 +370,7 @@ static void page_alloc_uaf(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >         free_pages((unsigned long)ptr, order);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[0]);
> >  }
> >
> >  static void krealloc_more_oob_helper(struct kunit *test,
> > @@ -455,10 +487,10 @@ static void krealloc_uaf(struct kunit *test)
> >         ptr1 =3D kmalloc(size1, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
> >         kfree(ptr1);
> > -
>
> Keep this empty line.

Sorry for my bad habit :\
I'll restore all of uneccessary removal/adding line.

Thanks.

>
> >         KUNIT_EXPECT_KASAN_FAIL(test, ptr2 =3D krealloc(ptr1, size2, GF=
P_KERNEL));
> >         KUNIT_ASSERT_NULL(test, ptr2);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *(volatile char *)ptr1);
> >  }
> >
> >  static void kmalloc_oob_16(struct kunit *test)
> > @@ -501,7 +533,8 @@ static void kmalloc_uaf_16(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> >         kfree(ptr2);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, *ptr1 =3D *ptr2);
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, *ptr1 =3D *ptr2);
> > +
> >         kfree(ptr1);
> >  }
> >
> > @@ -640,8 +673,10 @@ static void kmalloc_memmove_invalid_size(struct ku=
nit *test)
> >         memset((char *)ptr, 0, 64);
> >         OPTIMIZER_HIDE_VAR(ptr);
> >         OPTIMIZER_HIDE_VAR(invalid_size);
> > -       KUNIT_EXPECT_KASAN_FAIL(test,
> > -               memmove((char *)ptr, (char *)ptr + 4, invalid_size));
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test,
> > +                       memmove((char *)ptr, (char *)ptr + 4, invalid_s=
ize));
> > +
> >         kfree(ptr);
> >  }
> >
> > @@ -654,7 +689,8 @@ static void kmalloc_uaf(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> >         kfree(ptr);
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[8]);
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[8]);
> >  }
> >
> >  static void kmalloc_uaf_memset(struct kunit *test)
> > @@ -701,7 +737,8 @@ static void kmalloc_uaf2(struct kunit *test)
> >                 goto again;
> >         }
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[40]);
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr1)[40])=
;
> > +
> >         KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
> >
> >         kfree(ptr2);
> > @@ -727,19 +764,19 @@ static void kmalloc_uaf3(struct kunit *test)
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
> >         kfree(ptr2);
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr1)[8]);
> >  }
> >
> >  static void kasan_atomics_helper(struct kunit *test, void *unsafe, voi=
d *safe)
> >  {
> >         int *i_unsafe =3D unsafe;
> >
> > -       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, READ_ONCE(*i_unsafe));
> > +
>
> No need for this empty line.
>
> >         KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, smp_load_acquire(i_unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> > -
>
> Keep this empty line.
>
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL_READ(test, atomic_read(unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> > @@ -752,18 +789,35 @@ static void kasan_atomics_helper(struct kunit *te=
st, void *unsafe, void *safe)
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
> >         KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, =
42));
> > -       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, =
42));
> > +
> > +       /*
> > +        * The result of the test below may vary due to garbage values =
of unsafe in
> > +        * store-only mode. Therefore, skip this test when KASAN is con=
figured
> > +        * in store-only mode.
>
> store-only =3D> the write-only
>
> Here and below.

Thanks. I'll change them..

[...]

--
Sincerely,
Yeoreum Yun

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
LVzNmN%2BG/usuJoE%40e129823.arm.com.
