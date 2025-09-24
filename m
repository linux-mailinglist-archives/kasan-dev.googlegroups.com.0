Return-Path: <kasan-dev+bncBDZIFAMNOMIJDWWPYYDBUBCOI272Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 41FC2B99F91
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 15:07:31 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-45f2a1660fcsf54090405e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 06:07:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758719250; cv=pass;
        d=google.com; s=arc-20240605;
        b=h6Ib9txirPsG0otBviUfrJmE66t+us/cxG/LnrCgAjrSQLpt5UNAuiPWEBNWLCr8VW
         hFjdcETi4ovI+aM1lic7IuvXZhFvX0mgI0ZZ3uZrkDfQQ2CPFSYu/2S4WJefPPMIr6Su
         AAnOYNzcHubCzbQyuPB4+SWky4WO+aXYDYDLSNtfCfbd83qtC8NYSgZ9mvwUAXYuVdHL
         ix7nnLmPnpsd0f8gKdWMWnIO2J5hppevaJqlepfkREMjmEpW7PV4SJPFi4nUI2178A/H
         L0egsB93aVyPEN5UWc2AErZyfgosD64Ttuh3NWsneIP0ocpmZH0yNnCJRBBVxB6XxcPY
         yKZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:ui-outboundreport
         :content-transfer-encoding:in-reply-to:from:content-language:subject
         :references:cc:to:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=B93HKZ0LJ6Rxectqv7DjoKPYjWSB7ulpr+DmeyPar7o=;
        fh=BT6GcSNnAMshWF6YZskoEOwYWBxpdKkogLg+WHxxt3E=;
        b=Y7nRR6ES8RyxKhqtUgCyyByIi+6+dDglURhibqoVXWtZR8k/Bn2Sd3V77RBn7qukCe
         ewZqsEsoS6TUhgbWMU8SOOwG/WA7kWVXRCdgDFIC3qBEwe+6mF+UWpbDs6i0aELLw83L
         eWMinNNlfs/xHZd/iKab6HzbWo08cnoxJxqVYiAqXzSnf4yK4pwPTb4v3uHC04v/i+IK
         xwgX24im5DxPH50sIy//zH+sCeMHRwoZUUbXmYr2+hvR49POt1ZghF8x6mEdudmZXFOx
         PRmQyvWQi8stzWDRiWoNCAX6no2sgI8Xhp2y60bzSsMzvUu4BgXUX5Yk9sLkzTRbvGQu
         bj9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@web.de header.s=s29768273 header.b=i3MxGX53;
       spf=pass (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as permitted sender) smtp.mailfrom=Markus.Elfring@web.de;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=web.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758719250; x=1759324050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :ui-outboundreport:content-transfer-encoding:in-reply-to:from
         :content-language:subject:references:cc:to:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=B93HKZ0LJ6Rxectqv7DjoKPYjWSB7ulpr+DmeyPar7o=;
        b=oRyzDdPVdvmfr4LxqWfVDt3f+Gt3b87Y3MM3Rt6410R3WQM2dUqA/cAW87o7lKywsp
         ZvOIk74/ZkyBZgpgX2R5ex4/y70SGOKLNWdcGTOpOE5w3rERaB4JtcbSdRcTXkcUHvzz
         3twGToaAdO/xFaJ/upl23pmiQVD+9jeI6ExACjlbKS3MpLlQ723wZjFUXZ4S9w1R5dNp
         BEYx6YJz6xHjnF9lvVaDvvihTGlW00awGjdMid/b/4IxA9G7jUAlrqmoXhZMj8fqxKMA
         xaQ8QGEPndgWyK6FMypljynDwkKC7wtgWBuL6kjV1DsiELkX9XntG5eWlfmBf9smxsZC
         LQYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758719250; x=1759324050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :ui-outboundreport:content-transfer-encoding:in-reply-to:from
         :content-language:subject:references:cc:to:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=B93HKZ0LJ6Rxectqv7DjoKPYjWSB7ulpr+DmeyPar7o=;
        b=UJUc5PAsZoPPI6iYcRAH9SjY9vl/OhyTBepnRs4CrgBuFAuj+OxyVXm6cPciAgqSqL
         YBAGZkhXR6JHC3cAtX5RE2iwZm97tMTR7TJkUIS8SpBTPqGTKcI+J10FUm0ebsslJHcB
         G4/+lVNx4oqxJqBw7miDvoW/ptpNvfdvonZd75taJ2JWGX37XlWfju9rMGmd/PpELyjL
         RBVvXoKb105PaEzl71IAwvLoEpOZeD08gU5g4Vg4BMsqva44f4N6S+IPXW/53Dd2NwbC
         ykyR28A3n415dcClgNIfjjJTXdYPBi8Or5YcJn/uqTff/TpYf1LWj34UfpCknEPIZl86
         5w3w==
X-Forwarded-Encrypted: i=2; AJvYcCUCarTQKvXSN7FDJy3Q4mwMMw9Qz1zZCT/xUr25m0F42c2TC6B7+KZtPwaKDbacdSe7KrXR5Q==@lfdr.de
X-Gm-Message-State: AOJu0YySKBkOU7E97CY5kzqVBSAVLsLAQ/5Zf+J8bwyrblzM1Sf7so3c
	AtL6MW784CEI488Mfv4n9KFw/70mcX1H0JBWidp0kA0a87GPTnv9uwYs
X-Google-Smtp-Source: AGHT+IGZxnbJnYVZP/MqMEkM4ty42S0vgTW5P0nf6ITPs2pweDtBBUjg/FoAO9aWkA3TtOUczY0atg==
X-Received: by 2002:a05:600c:6288:b0:46d:996b:8293 with SMTP id 5b1f17b1804b1-46e1dab26ccmr55432735e9.22.1758719250394;
        Wed, 24 Sep 2025 06:07:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6FcS79cdEjM0OlcjYN7uC+7oAHJtlKnWKT/TzfAEa0RQ==
Received: by 2002:a05:600c:8812:b0:46e:1d97:94c3 with SMTP id
 5b1f17b1804b1-46e1d97965als7014775e9.1.-pod-prod-09-eu; Wed, 24 Sep 2025
 06:07:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVWYPyLPZ2aj1M0kgLjgSyyho2P2FPHP7mQVD8fPqiVitheoME1vZMT38wl9qeDerNPeYEXcWOgfq8=@googlegroups.com
X-Received: by 2002:a05:600c:4683:b0:461:8bdb:e8 with SMTP id 5b1f17b1804b1-46e1dabfaf3mr71837825e9.30.1758719247725;
        Wed, 24 Sep 2025 06:07:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758719247; cv=none;
        d=google.com; s=arc-20240605;
        b=AmZm8zcbRiasmTTr+InP4tg1CnGnsZ2kdaXh4F80rl2i0t9RhBHmdHRMdUKj1pQu0u
         FkGcd73qiuCcLje4moz2tigmuTlJGsqQAipzidMNFn9m0pvGHWFF3Wz32Sp+3P9daIMF
         uF+QRWvqXa6LUMNAAhd1wNwt6/TUVXB7DVQs+npWoZfbLn9+5PcbpUNkY3Vh8ywMJ6Fm
         uwTXiTZ6A3XaK13JuRlmwh7gVQP+ixBeJwVJEPGK0lYcTjwhGLX0TH6E0RKOWFniq3uy
         FiS+rrkegFo0382Ra5JEJw8tDyX+r4cmE85HMF98P2pdJKkAhNEm+p9awNEMdturvOUC
         +Mdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=ui-outboundreport:content-transfer-encoding:in-reply-to:from
         :content-language:subject:references:cc:to:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=OdGjjsFfxm07FUwZBmeZuXP/mxTZFmQCW5oypD8AB9k=;
        fh=rJrci2Mk7UYFZFEq5EX3Wk1Btuo+HnU1GbKUIpi4htk=;
        b=hYLZ1rog5brRstghiWqrTLXbZJCNfkiYj7qAmvlcxKLgTrCeXhtYTmqJz+Sr9X8gxi
         1EEl29S5/P+pC7lsZJxHqUlmYSbcO9foKXUOd8McsYlKXT/cApFUcv4a0/ohi6vSTyJv
         Fgt5Lfa8ltqu4fDMc4KUpK7hJ8mhLD3eNBe43mC9mixpe3m1CHk1sqRcfswJVXisdAOy
         equZzwTwrLijb7j1mFm41T+H2HkHaZg422nvU4G3AQm/0yxNyXh9yawsvH/Ep7VMavfI
         m1SiRQZRdejlrxSBdv2CPbyOGT1ylMAyAqijzf1CBNuazXCpRmoaHNsUDieiCjUSWQpc
         a+3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@web.de header.s=s29768273 header.b=i3MxGX53;
       spf=pass (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as permitted sender) smtp.mailfrom=Markus.Elfring@web.de;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=web.de
Received: from mout.web.de (mout.web.de. [217.72.192.78])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ee0fbcabecsi370553f8f.8.2025.09.24.06.07.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 06:07:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as permitted sender) client-ip=217.72.192.78;
X-UI-Sender-Class: 814a7b36-bfc1-4dae-8640-3722d8ec6cd6
Received: from [192.168.178.29] ([94.31.69.191]) by smtp.web.de (mrweb105
 [213.165.67.124]) with ESMTPSA (Nemesis) id 1MRk0W-1uu9At2VjO-00OPr1; Wed, 24
 Sep 2025 15:07:25 +0200
Message-ID: <a1eaa2bd-3e0f-4871-aa57-d7f9966178a5@web.de>
Date: Wed, 24 Sep 2025 15:07:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
To: Alexander Potapenko <glider@google.com>, linux-mm@kvack.org,
 kasan-dev@googlegroups.com
Cc: LKML <linux-kernel@vger.kernel.org>, Aleksandr Nogikh
 <nogikh@google.com>, Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, Dmitry Vyukov <dvyukov@google.com>,
 Marco Elver <elver@google.com>, Mike Rapoport <rppt@kernel.org>,
 Vlastimil Babka <vbabka@suse.cz>
References: <20250924100301.1558645-1-glider@google.com>
Subject: Re: [PATCH v2] mm/memblock: Correct totalram_pages accounting with
 KMSAN
Content-Language: en-GB, de-DE
From: "'Markus Elfring' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250924100301.1558645-1-glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Provags-ID: V03:K1:SFNX8XgpMpqmZ8DFGyqHU/flC0dMddIahNCKi+wLKgzOcsrK+q+
 VEgkUaBXW6MC6RSJV/hisVggNpvBdfIFZM4CDwB1eQhlhNM339o8WZtj8AKd85CPq1fE5y2
 LaQTHPvlE8g/k6+vQrkJ1IXVWJHqZqozhVc1+GeGF9q2Lpt1uSW3hihtGCxVVeJgvt265Vx
 BI5TVmS11apeqEBt6M/TA==
X-Spam-Flag: NO
UI-OutboundReport: notjunk:1;M01:P0:EuAIvhGxH8c=;L+2hPOxomEmsD70I1x5BNSGi48V
 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
 I99lVDE3+0CJlmBw5cmhEcQewOvqMGXoW4Io3
X-Original-Sender: Markus.Elfring@web.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@web.de header.s=s29768273 header.b=i3MxGX53;       spf=pass
 (google.com: domain of markus.elfring@web.de designates 217.72.192.78 as
 permitted sender) smtp.mailfrom=Markus.Elfring@web.de;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=web.de
X-Original-From: Markus Elfring <Markus.Elfring@web.de>
Reply-To: Markus Elfring <Markus.Elfring@web.de>
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

=E2=80=A6
> This patch refactors `memblock_free_pages()` =E2=80=A6

See also:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Doc=
umentation/process/submitting-patches.rst?h=3Dv6.17-rc7#n94

Regards,
Markus

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
1eaa2bd-3e0f-4871-aa57-d7f9966178a5%40web.de.
