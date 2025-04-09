Return-Path: <kasan-dev+bncBDEKVJM7XAHRBEN33K7QMGQEEHN6KQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EAF9A82C1D
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Apr 2025 18:17:24 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-602a52f7183sf2986312eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Apr 2025 09:17:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744215443; cv=pass;
        d=google.com; s=arc-20240605;
        b=JWABe5MMO7lYiLc3/kuQaAsS1S3r/gqmGjfsUtWIz6FeJhZossMDV9HMEGEcxEDpx8
         do379ftK/qnIbByn2Gg6C3v5k2GzXBaP8W4YRS7AKURx+KcnkXL20AxB4SyenkYyC+1I
         PFh7HhIiTnSubA2alhVQ8rt/aZ35M7w5h0dgVf6/AZ2EaQAdet66lELarqAEJFqkmiWS
         NH/bJhEHrcIyNOVBDPfYS3HjyCnXrATCWUj/1Yljg9Umvf8EllMcK4UuF5CNgy5Q+K3q
         urVeZlxwOhiYFTntEwsrH4t08CHZywLlzTf0e8ESbcfrInO126okdJ08qH0SJbzHD0WB
         iRRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:references:in-reply-to
         :message-id:cc:to:from:date:mime-version:feedback-id:sender
         :dkim-signature;
        bh=Q+vm08A8tH0tQZs6MBw4LOQGbEBAZvqTgicRnnCQg9A=;
        fh=ltlfR3/vy7v8pDRM8rtF9i9uf7At4Ai/Ou9mqJyrK0A=;
        b=ImfKZ/eEbG389Mlh381yaHH8m678+EQcOez48fyTj0YjuPP4/KPzm1n3i+E/jqX6dI
         nbdH8D61xbp00wm0KI0H/09YM1GFAMdC2D7Cg2Jy2AC6mnWwz8+dI3/HPSmwtxVenwJM
         sIVsfYF9CIem+nzdg0jLBDXktR3uY4Zikq1+HAxnAKvaTkHtIIqL4a/zDqO7N2/56ddR
         V3231Du77XdH1MJqEQFK302P7uouuB7c3rWoU+2qlrD0l2CZJr00PJ1TyYesDJcVo0o7
         Yw/RAF4sBccI8pstM5MnKYo1KIAaRNaMX/35rYQmeoIapiKQZrk025pH2FfeCjKUcx+U
         Cguw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=BIC2fPhu;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=lrNjiqBJ;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.157 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744215443; x=1744820243; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:references:in-reply-to:message-id:cc:to
         :from:date:mime-version:feedback-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q+vm08A8tH0tQZs6MBw4LOQGbEBAZvqTgicRnnCQg9A=;
        b=kjr9bU0mKBnPNupkR+/QX7qeqtQmvcyH7eqRrUwyYVQ2u9FeY2xeAD9bh/NI6ysSUm
         spsX3cMZQiY4bImoxy4JAzjdNBSnnSRtTU+piXA2nu0MgZpZO8VQfwWqtscxOSRh325f
         Wiclh3FE5c+r8PzG1/KlZsbEo/SmINmurBck6pjoA2eQgc5Q+15xkV4aiLzBAH1ZY7r1
         p14YVueCWgoAzRyehKKL5I13B/27D7hMZ7m7bFugRh5r+8gUh1pA4uhXFeQD5JDDB70Y
         1ebdBZandXbB/lqSX2leWza1YHlkHk0mtVJ/NSlmu9YsUvf21AJagHQG6dHnn8Ip/8yx
         aH7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744215443; x=1744820243;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject
         :references:in-reply-to:message-id:cc:to:from:date:mime-version
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Q+vm08A8tH0tQZs6MBw4LOQGbEBAZvqTgicRnnCQg9A=;
        b=nEgdhFYa8jFeO7hVP1oecpPmdg9/owjGewhbCF3X3RofZ1FtGGzcvriBoeBjk3ZKA6
         mKq2R7/gOldyYIXnLOCy49CPcAs/xqSbM439CYvF/EvV3Puqlb0VRLslnifcLNOlkWiS
         A7wHA1LJol5N4a3SDlp9zDdPdlAnndKzOk+GRax+wH70rwIeQaio2/Bwj/gP8OcG/rzN
         rqcrEeDXgGu22HYKomG4E1MChH1jIQ/2IKqyKwUwWF1JEjF0QpEjup/vPUPNRYiDkiKr
         pmfCoIBHnYgrKX8eWT32fWrKpcjPiScedAFk7xOzyvTxyuLFb7RyRVPKsDITAH3+WFTB
         8Q0w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWgU7+DrHiOXtMsv5LrRwvEiVfYTVbjI1m7xOHUjLXPDEvtpHKlVgZGDfgdhjpP5DyQ7iHYIw==@lfdr.de
X-Gm-Message-State: AOJu0YwLgjswv5eSRaPETHQSkrAnpkEYzWQFGJqKY1NpZCl1BWO/1pPh
	HDzspUtk/xNYEeAzapdGLvI8eiUhDwSpqTQ5A3K+EYhjVkq47lJD
X-Google-Smtp-Source: AGHT+IGyOg3VpnVPVMX/ye85p8RhfISjYN99Evad/Up3AfXGrBr5JKB3gnDH0qjBy2c/nPzD4O5EsQ==
X-Received: by 2002:a05:6820:1627:b0:603:f526:5e76 with SMTP id 006d021491bc7-6045daa78b2mr1469968eaf.6.1744215441512;
        Wed, 09 Apr 2025 09:17:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALarwoWl4n1SKs8SfRstiz7F3TaXZynFwM80pDuxMm28A==
Received: by 2002:a05:6820:800e:b0:603:f12f:5cf with SMTP id
 006d021491bc7-60464b031a6ls23274eaf.1.-pod-prod-05-us; Wed, 09 Apr 2025
 09:17:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXEKNrgmPT8+ihWe30Q10SFbdAVrHAotxUhyx+ayIbeHpf203zFqDbSGWw98LqrLn/2rilQgOFixU=@googlegroups.com
X-Received: by 2002:a05:6820:502:b0:601:af96:36eb with SMTP id 006d021491bc7-6045da894d0mr1439351eaf.4.1744215440654;
        Wed, 09 Apr 2025 09:17:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744215440; cv=none;
        d=google.com; s=arc-20240605;
        b=VN1dUC2HB01Tv0xRxdc07RjBvoTMAoNi1TT0K1ZXIR++GITK1/x+F1Aa2/mxAfSX4z
         S3XKpv66kx7W1qAo6nqM7YTI1rFbTRkFYfsJC2l3Wzs4bhL3hxLRz7IESI65rZrXr3T/
         iUp4Dr6PQPT8ttf7Ndkty19k3zge2znbWqPcTzE+MzC2obFrnpdNOPcOZewLsg8xdOQK
         2xHnCDyZPdkhM/QyWEirPZrGZeC4SYiEtO56Bw5gd57CVULKRrZRtmW5fOqbwnXprAGv
         Ps5I/RaFhdLNHDTIEet2vzKyrfvy6r/StP3vQuSuU3OD69jzdiTcS/NESmgsXrLkWfwx
         U6rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:subject:references:in-reply-to:message-id
         :cc:to:from:date:mime-version:feedback-id:dkim-signature
         :dkim-signature;
        bh=6yCL3QYH4w/BEqNIYYKQKEvXiLPGj6zFsd+qqSWKc2o=;
        fh=rILHwwZk9KaUQDk6+kDRdUdYi+xPL1H2tbKsGwhzubg=;
        b=YMzGuWlyWeO4igS615a6PsDS69N5PmidKLJmOCwjBt/bBxZTu/qCJqehRsoCOyY6Hz
         nm9kEFM663eoMuAlVbC9q+ApnNLZ9+b2pVpelWsnLhgDhbG4WiippD5PaYmFEg4eC0ak
         0ZSpWal7xBBQGzcJUp2T4EV/fShHrhHf5/Fk+HOfktsJUTGsLXVCG1R84NNyCznXrzu6
         VATTxvXgPJtmwMH2ZFXkM49A+NNw2ziQEM0hRz/WMieHughfXNt8hDONVetdK88b280r
         h7dxuxI7ne1g9pQoMyPN2BS8qxpHyL0wWJiV5E9bpUwy6/fs/3uOecaIGgwvyFAYCRBJ
         NtNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm1 header.b=BIC2fPhu;
       dkim=pass header.i=@messagingengine.com header.s=fm2 header.b=lrNjiqBJ;
       spf=pass (google.com: domain of arnd@arndb.de designates 202.12.124.157 as permitted sender) smtp.mailfrom=arnd@arndb.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arndb.de
Received: from fhigh-b6-smtp.messagingengine.com (fhigh-b6-smtp.messagingengine.com. [202.12.124.157])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-6045f52b24fsi77424eaf.1.2025.04.09.09.17.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Apr 2025 09:17:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 202.12.124.157 as permitted sender) client-ip=202.12.124.157;
Received: from phl-compute-12.internal (phl-compute-12.phl.internal [10.202.2.52])
	by mailfhigh.stl.internal (Postfix) with ESMTP id 9693C2540102;
	Wed,  9 Apr 2025 12:17:19 -0400 (EDT)
Received: from phl-imap-11 ([10.202.2.101])
  by phl-compute-12.internal (MEProxy); Wed, 09 Apr 2025 12:17:19 -0400
X-ME-Sender: <xms:jp32ZzdgkZ65iEXkV1kwTPd-LkJxwkOOiA__J4G6FJrBahmqATDZkg>
    <xme:jp32Z5N9Ac2i03ezWLg0C4p59Jsor6WeXWdPyk-7becJwnKMkW6IZARqtnU_d56OT
    s8blHdeUmLMmgrlGG0>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeefvddrtddtgddvtdeigeehucetufdoteggodetrf
    dotffvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggv
    pdfurfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpih
    gvnhhtshculddquddttddmnecujfgurhepofggfffhvfevkfgjfhfutgfgsehtjeertder
    tddtnecuhfhrohhmpedftehrnhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnug
    gsrdguvgeqnecuggftrfgrthhtvghrnhepfefhheetffduvdfgieeghfejtedvkeetkeej
    feekkeelffejteevvdeghffhiefhnecuffhomhgrihhnpehkvghrnhgvlhdrohhrghenuc
    evlhhushhtvghrufhiiigvpedunecurfgrrhgrmhepmhgrihhlfhhrohhmpegrrhhnuges
    rghrnhgusgdruggvpdhnsggprhgtphhtthhopedugedpmhhouggvpehsmhhtphhouhhtpd
    hrtghpthhtohepnhhitgholhgrshesfhhjrghslhgvrdgvuhdprhgtphhtthhopegrnhgu
    rhgvhihknhhvlhesghhmrghilhdrtghomhdprhgtphhtthhopeguvhihuhhkohhvsehgoh
    hoghhlvgdrtghomhdprhgtphhtthhopehjuhhsthhinhhsthhithhtsehgohhoghhlvgdr
    tghomhdprhgtphhtthhopehmohhrsghosehgohhoghhlvgdrtghomhdprhgtphhtthhope
    hkrghsrghnqdguvghvsehgohhoghhlvghgrhhouhhpshdrtghomhdprhgtphhtthhopehk
    vggvsheskhgvrhhnvghlrdhorhhgpdhrtghpthhtohepmhgrshgrhhhirhhohieskhgvrh
    hnvghlrdhorhhgpdhrtghpthhtohepnhgrthhhrghnsehkvghrnhgvlhdrohhrgh
X-ME-Proxy: <xmx:jp32Z8jhWNUNs_fGPEwj7VXCuAZ-OSBHky21rJzSv_C4iQAECV4b7w>
    <xmx:jp32Z08-9Yq_wYejE7bwe2RdYallQdJ2OI7ufSn8fv31rsUURBFpQg>
    <xmx:jp32Z_tFfq-ue-j7rEcqfOgDEna_D6_HYkY_p2ZBPww1s4NG31_ocA>
    <xmx:jp32ZzHq7dkQt9pI32EaIrDnq9vN27ZLtG4iXiFAz5PHOt0-3zHhMA>
    <xmx:j532Z4r6N7xgeqO_1YO1xL9sDbbPqhsupKI8FDSAONyYX8xO3xVxacgn>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.phl.internal (Postfix, from userid 501)
	id 818DF2220073; Wed,  9 Apr 2025 12:17:18 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
MIME-Version: 1.0
X-ThreadId: T654dc7563e4388c4
Date: Wed, 09 Apr 2025 18:16:58 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Kees Cook" <kees@kernel.org>, "Andrew Morton" <akpm@linux-foundation.org>
Cc: "Masahiro Yamada" <masahiroy@kernel.org>,
 "Nathan Chancellor" <nathan@kernel.org>,
 "Nicolas Schier" <nicolas@fjasle.eu>, "Dmitry Vyukov" <dvyukov@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>, linux-kbuild@vger.kernel.org,
 linux-hardening@vger.kernel.org, kasan-dev@googlegroups.com,
 "Bill Wendling" <morbo@google.com>, "Justin Stitt" <justinstitt@google.com>,
 linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Message-Id: <32bb421a-1a9e-40eb-9318-d8ca1a0f407f@app.fastmail.com>
In-Reply-To: <20250409160251.work.914-kees@kernel.org>
References: <20250409160251.work.914-kees@kernel.org>
Subject: Re: [PATCH] gcc-plugins: Remove SANCOV plugin
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm1 header.b=BIC2fPhu;       dkim=pass
 header.i=@messagingengine.com header.s=fm2 header.b=lrNjiqBJ;       spf=pass
 (google.com: domain of arnd@arndb.de designates 202.12.124.157 as permitted
 sender) smtp.mailfrom=arnd@arndb.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=arndb.de
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

On Wed, Apr 9, 2025, at 18:02, Kees Cook wrote:
> There are very few users of this plugin[1], and since it's features
> are available in GCC 6 and later (and Clang), users can update their
> compilers if they need support on newer kernels.
>
> Suggested-by: Arnd Bergmann <arnd@arndb.de>
> Link: 
> https://lore.kernel.org/all/08393aa3-05a3-4e3f-8004-f374a3ec4b7e@app.fastmail.com/ 
> [1]
> Signed-off-by: Kees Cook <kees@kernel.org>
>
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 1af972a92d06..e7347419ffc5 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -2135,15 +2135,13 @@ config ARCH_HAS_KCOV
>  config CC_HAS_SANCOV_TRACE_PC
>  	def_bool $(cc-option,-fsanitize-coverage=trace-pc)
> 

My version removed CC_HAS_SANCOV_TRACE_PC as well, as I planned
to have this on top of my patch to require gcc-8.1 as the
minimum version.

>  config KCOV
>  	bool "Code coverage for fuzzing"
>  	depends on ARCH_HAS_KCOV
> -	depends on CC_HAS_SANCOV_TRACE_PC || GCC_PLUGINS
> +	depends on CC_HAS_SANCOV_TRACE_PC

So this dependency would also disappear. I think either way is fine.

The rest of the patch is again identical to my version.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/32bb421a-1a9e-40eb-9318-d8ca1a0f407f%40app.fastmail.com.
