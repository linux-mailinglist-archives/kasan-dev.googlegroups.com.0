Return-Path: <kasan-dev+bncBDHPTCWTXEHRBZ5222OQMGQEFNG3NNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 76B4F65D757
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 16:38:16 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id j18-20020adfb312000000b00293def622d1sf1733641wrd.17
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 07:38:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672846696; cv=pass;
        d=google.com; s=arc-20160816;
        b=Iqxp3+k6kCT2W/gEa1ULECR8GamU9kFTEwZIfn9w5yF4PiQ9yAOdYL20/ojxbX66Bx
         Lzd4TJTVSO88n6pyk1qlV1eI4lSfKMLKvvXavyz2zIyVJMllUNoxczj3Y+OCIgs5m1bc
         8/jIVXNoz02PgJGoeF9d/bSXhdIHEDGR/SuTrOPjF6y/aigx0m9IkXobS0q9Y2WhQ46P
         jZV0yMdW02MiMB50uQVOuLPV/iEwvwxG+84GQbk2xftpcYLdMPuvjgDEc8CdGPqgUcN4
         n3n3iPSuw9OsijPQSZTZJ+SmZF1AhgR/8P8DqqwtJ4SEss5pgZ3wDrOP0QTwEFY+vUPu
         lGmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=igJZnTu+iyXG3aPMioyk6SH9FL/4xLPMbn2/aGCrdco=;
        b=xWXE9dSYFxX42mAbjngmWZM5IE0hvzyzqkOoJJUi8wsvIWtypXkXSdZw1AUUGSPcak
         I+Gpe54jKZSuVF2yK7R0U1+jFsjpRrjAuGYCNqJi/bR9RSvSJOeZ+pRy0j0DTN2JfKnG
         bca70ZUiUduAD2aUGc9qfrEM89Ktth8qsyyw3KRI1dSl9wGfC8x2iVyaplaP1eq+nzYg
         w+OsKPo/E4KPkVEqmLLNlBoECOGyXwvmyHeReskfs022RX2iL936xm6LB84kHRGospVw
         0tMQ1AzC1JQQ75QpNrZg/6wWXKxZqIqzCguCOt7XaY4UWTWGnV45Y1K0630XQgxF85Mh
         7Q1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of heiko@sntech.de designates 185.11.138.130 as permitted sender) smtp.mailfrom=heiko@sntech.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=sntech.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=igJZnTu+iyXG3aPMioyk6SH9FL/4xLPMbn2/aGCrdco=;
        b=bfvMl5/Xb+zyNGdJNMp3N6YFWfVurj7va8eDgIprZz+QbYXlU7m4UiDwv+a2IhoFm1
         CMNrNcSguzoUNs151Ovx8f86k9zb1eRBWsOwbos834e8neDv1BKPVGa9EQoEwWrdn1Xh
         Y59fB2Duf4K1JRB7vk68wZusOzYBBU8aBVviRDKQNfsW5ngbjaKIh7Slbc0kTT/L51GN
         9PVUmzHlRgBkhU1Z19396ahtfXspHY4A+WSfMTbzU9C81cUcu4NowP9U1nJZs5MzN3+b
         y7gjp4oI368UrrYvmS8VJFMpIT6zzpStsGWM/qZC3Gnk9iyhTxnQt56XV4dchETToX/P
         6Q4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=igJZnTu+iyXG3aPMioyk6SH9FL/4xLPMbn2/aGCrdco=;
        b=R2jnpzNycCLceW7/TcaNYV47wghl46TzRhAQv7oQrfKYi8dgNJLA45BCsOAQNfq/rA
         76/j5k3u5AAxM8ILTyBQQStbH5owF382x8ZOqNjq+1fs2QiMpPq5YguJ6QfT3puNoThu
         6EX0sxYobORJBZufEDG6DMNnDvItmM3lLqyYVUnztNZt2xmYmzOvnQ4ck8BuX4Obpexk
         pFrnW/HnrpsVtugvevaGuESgtqgsl1Ydo8Fxljt7+y5TulAzmJY8iUQRVbPic95TqzFv
         wgpzMH6MlkCHvWP98UIQPCLkdmR4efk66eD9NUBJzqzRF8ECbFdP3+mvBzuqDe4j5QMv
         CUtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqMR2n+ge+OqH+b/WIcF/A/0u3f4BaEtUq90wLMn2M0USfIYNgn
	E0mTUmZBQqjhri1L29HNtCM=
X-Google-Smtp-Source: AMrXdXvG+OxsOwzk6Gv+7S285iKfgtW/nYk/zZlMXb4BsSY1N2rxqJYd5mbmm+mmJzj5VuDayIwubg==
X-Received: by 2002:adf:f60e:0:b0:27b:7b34:5cae with SMTP id t14-20020adff60e000000b0027b7b345caemr908990wrp.484.1672846695915;
        Wed, 04 Jan 2023 07:38:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c9f:b0:3cf:72dc:df8 with SMTP id
 k31-20020a05600c1c9f00b003cf72dc0df8ls19059072wms.0.-pod-canary-gmail; Wed,
 04 Jan 2023 07:38:15 -0800 (PST)
X-Received: by 2002:a05:600c:b4d:b0:3d3:49db:d84 with SMTP id k13-20020a05600c0b4d00b003d349db0d84mr33398048wmr.20.1672846694974;
        Wed, 04 Jan 2023 07:38:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672846694; cv=none;
        d=google.com; s=arc-20160816;
        b=SY1wGv1NQLUCV8NMHUAw230XWN/cCuzY8fRWz/6JqmGNWLVknNQ/O6PTiK6jBuq1tY
         46vTCCmiu9sEUDhjgFN4guM3xVIHMnWzLidD6qhP1QhFiMt9jgS9QqdhLoNhMcazKenJ
         s0/1gTfCtbNnBFmqstZmkrZhYzw2oCaj77t+GuNVYaICHJ6+DPc0ijyK2EGhyGxV0A32
         2Y7tWS6NEpCfQiBY5+YkAOA7/k6Y1Hh93rjgziZ/U3mOF+iGGqr7NHBQrF8Gplu8Tfbp
         Px3+/DNZKrEZQRYcuP29IYfbednMPyyuf+VfJcditUE2zefKYvx4eRm7cjqMveN2fNqZ
         4IWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=sYER8cCHCls1CzPezQ2JcVTrRBYvfOGFLKiB1MYwV7A=;
        b=Tcjn7AX9uLIWp2bJvPm6VG4kNWzR1/k4oArXNxPSMFm9BKae3Eulc611UvmjBriFLv
         FB0g9iHE22G23os/7Kk7rFAtPEOVuuyWuvxPSaiO5dhdyC4GX0r1z2pQYoXHRLyWe1FF
         8lrMMYpcsi3f/TxHd7Ymc8i5USRznYIv3LEaoxNYQFOQQNIain0UlbJFp+65ftsTwxFE
         PUDorp2esy8ikTf18EwMqeYKh/j8DVo1a83XYe2xryQe4YwKHf9kUqTo2pjEgMtl+KQ1
         1yYOj4RiY4oCVCjb3N68ZX4WyOXt02n1v0cCr877vUzvmiMl7YVW9tMHrY6XDvEnpns5
         PB8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of heiko@sntech.de designates 185.11.138.130 as permitted sender) smtp.mailfrom=heiko@sntech.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=sntech.de
Received: from gloria.sntech.de (gloria.sntech.de. [185.11.138.130])
        by gmr-mx.google.com with ESMTPS id r65-20020a1c2b44000000b003d9cc2bca83si52351wmr.0.2023.01.04.07.38.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Jan 2023 07:38:14 -0800 (PST)
Received-SPF: pass (google.com: domain of heiko@sntech.de designates 185.11.138.130 as permitted sender) client-ip=185.11.138.130;
Received: from ip5b412258.dynamic.kabel-deutschland.de ([91.65.34.88] helo=diego.localnet)
	by gloria.sntech.de with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.94.2)
	(envelope-from <heiko@sntech.de>)
	id 1pD5qA-0007gv-QA; Wed, 04 Jan 2023 16:38:06 +0100
From: Heiko =?ISO-8859-1?Q?St=FCbner?= <heiko@sntech.de>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-efi@vger.kernel.org
Cc: Alexandre Ghiti <alexghiti@rivosinc.com>, Alexandre Ghiti <alexghiti@rivosinc.com>
Subject: Re: [PATCH 4/6] riscv: Fix EFI stub usage of KASAN instrumented string functions
Date: Wed, 04 Jan 2023 16:38:05 +0100
Message-ID: <10490920.nUPlyArG6x@diego>
In-Reply-To: <20221216162141.1701255-5-alexghiti@rivosinc.com>
References: <20221216162141.1701255-1-alexghiti@rivosinc.com> <20221216162141.1701255-5-alexghiti@rivosinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: heiko@sntech.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of heiko@sntech.de designates 185.11.138.130 as permitted
 sender) smtp.mailfrom=heiko@sntech.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=sntech.de
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

Am Freitag, 16. Dezember 2022, 17:21:39 CET schrieb Alexandre Ghiti:
> The EFI stub must not use any KASAN instrumented code as the kernel
> proper did not initialize the thread pointer and the mapping for the
> KASAN shadow region.
> 
> Avoid using generic string functions by copying stub dependencies from
> lib/string.c to drivers/firmware/efi/libstub/string.c as RISC-V does
> not implement architecture-specific versions of those functions.
> 
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>

I think a similar change already went into 6.2-rc1 [0],
though it seems to leave strcmp in place in image-vars.h



[0] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=da8dd0c75b3f82eb366eb1745fb473ea92c8c087


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/10490920.nUPlyArG6x%40diego.
