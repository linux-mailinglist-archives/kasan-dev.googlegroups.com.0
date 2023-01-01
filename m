Return-Path: <kasan-dev+bncBCQJP74GSUDRBAHXYWOQMGQEEFLGDQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id F1E4C65A9F5
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Jan 2023 13:24:33 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-1443ed029f2sf11417237fac.4
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Jan 2023 04:24:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672575872; cv=pass;
        d=google.com; s=arc-20160816;
        b=nIxba8uUo+K3nVWuwB2xM7Z8fdJg50vZFnUaNQHktl1KdwoaWL886o1xXdJBb9Mpba
         80ALVXkf3w9XgtTUmo1fsb0MDAGn23Inzb2zMFT0UxMu65o1nB0tz/GGl+zEEx84kWIa
         8oakxzlSjrz4X6kg/hESWNU9v9rxKqvUZ5mH20eYMuN7dYU/hfuoCsCikIUQhm2XTm63
         onK8dkNMeooeXIZGMDLd77ZXvMgW6IC+uVgFAXNb9F0pDSLPxqTqjsDgZTYqROMgG1JO
         n2h1tOZmfvzIPf0qoEbN5mWaxTnAtYAQRoehTwsdTIcCnLOLFWBpXxq5OPGJIKeLyGS3
         rMhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=IdSdziRkdKGuJVRWGzUG3E+fXErSFILUeUePY6nXHrM=;
        b=0tnaErEqBeCzZXF7XRE6lkFFdB6JznQYwvOKqHTrZDl+m/XWsHDQGFpZTT/QZMYQlM
         SBDCCiy7BIVGwmR4DFXVIED75zvZJA6AjmQLdkvkr7acErEhdyMlUOSEjD5hdsT1otbu
         8i0l8ZXnFE26dR4LX3J57zh3X6/FAsbQA7SWOt05zf7Yg4vMu+ND5n8CSddfwt+TuuSY
         8ij+HPZybIghoj+RqJoBHEBMQL4FadrDwm+l1PUbgvAtM6QkrCkwNkzNcDYlq9T/ZZ+z
         FlE+/arE8mlPJ69JCX7qn8r/tQGaX+Wbc1y3djv3Otgycxdr8I2yc2pcy4fA890wrYy2
         Beyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.169 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IdSdziRkdKGuJVRWGzUG3E+fXErSFILUeUePY6nXHrM=;
        b=NwvSSa28H8Uyh48S9/D4p1ps5jphz+4mEcINDV1f2uN8qey71PuOSxooIFjPXe9SJD
         Zwf3Y7laU4ZHJ0e0Bs7KEWOxORlWwUaJj57H6QwE4PZ33rf3AXsGYrA4gkX5N8sJRNnh
         XCAdPTVpbormVTKnaPi+svsV19ePjh9n6Of6AvwniiweOLOHNgfQGEBU3AmgCYu6di2Q
         wzkNnNtbbKNOdFxq+Bh9jOB8v1P/CzyzkAhpWtp1lOmPHB5CnUfGOYcFLVIY9k81ystn
         9lzUbYBNetMmLgPVeULzodT9YSnT3ZQfcI6wpy8FYkJJUxgID3Qx4tKqLJPmM1kcVwSR
         HhoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IdSdziRkdKGuJVRWGzUG3E+fXErSFILUeUePY6nXHrM=;
        b=4gNDw2mQoBgfgPiNWXtVnPSgdzKW0KJQv9NSNj/GJqyVcudFVREU0NbIwQYrm19daw
         GzX88L5Hp9Pp5r+YNV3KFjbyyo1+O8zcl76weDn6H0OG/Jzq6EQ+DpqGGBYmgpry2UGc
         Ws+Ha1EeBC6o7cVkyfsW8lu5e+efQgc9jYDXc78PDSfPMqTBVDdzEZmz/CWE2XzNwQqq
         s8H9HjJAEi2627ZOmjoTGT+cEyNp693IRUHamGQUNfLSszBkf/gSLHFmLk+R0R8YmWO+
         WozHemc+FdAJYbDucopAYjWE05BILDTMqZHyETMFzGqgBeb+Dp+2LgMo3HptCZwc6DbF
         AaMg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koH3Iy2zzWYD+2V9U0vIBCQQVS6YAB/kvNnOOgVKFPX67e7v1sk
	lmZQ9B22L5tZ4BacdIPal40=
X-Google-Smtp-Source: AMrXdXu6BjiogyVX3P/8LQKcppp5N/8u3sdqKOma4V47PzVJKiNzGyY1fB/ud+OsGOofAj3ad9vMnA==
X-Received: by 2002:a05:6870:1f05:b0:144:5572:4af6 with SMTP id pd5-20020a0568701f0500b0014455724af6mr1639534oab.230.1672575872539;
        Sun, 01 Jan 2023 04:24:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6185:b0:150:5959:52ad with SMTP id
 a5-20020a056870618500b00150595952adls2456260oah.3.-pod-prod-gmail; Sun, 01
 Jan 2023 04:24:32 -0800 (PST)
X-Received: by 2002:a05:6871:4105:b0:14d:8a5d:6ff8 with SMTP id la5-20020a056871410500b0014d8a5d6ff8mr15122798oab.32.1672575872019;
        Sun, 01 Jan 2023 04:24:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672575872; cv=none;
        d=google.com; s=arc-20160816;
        b=RBCc3zPFaoNr2DsOfAd/3RKR+bK9SbXsdjWiGxrm0blGRG451Mu8NW9IFxdoKBaWOe
         MJumG4pSjlFC0KOkuUZngAsi4WyNaNxckkb60CU/jizWE5yllHaup2ZAOIaBQliZhF8w
         w5S58vl7Vps5iz8u9PU4bixCHlJvwJ6YCgcDOW4aJi+onw8+BxW7WFy/t4cHe/m2jrcG
         hcp7ldHyX/OY10B86qx2jZMMwaiL3rof1bYSMlFMCRYBfRwVLIZjEykBUcC8J9OiiHEa
         57/M2PyJSiffYCL/V3GOQb1Sn8VyVrn//T2j52T0657TnrypviXjHljLMzExk1NvKqNv
         hspA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=WU4mZYTUdP8Bxx/sJlJybQ4hqWHwyg4u2SGVhjlH2Cc=;
        b=BGl052QhL2xJPMglyS6eLbPvRCR1Ypqs3Sh/18xE4iyqkH0kfLXxkQr+fmg5nD7QuR
         svk3m3egC55kGBbjZfePQQywNIxtWrYsfJBYQx+f+xjQ+BUk/tQnilUoNiBL8yhhj3+B
         GbHj9p9ef+TBJ4rUaHJCntbCWYciSdmBOagCyVizt8v3mC6BELaidhch2zoVNVS7xttJ
         5WA1JrZlYvqVvNbXbfAGcif/qy4dGdyxTqH2Z2B+kJTP6E2YFb15232u4TPIE7D/YvjW
         A7xjWo4bFbKVZThDMW5rTH+/oUVzL6eQEhxI+EiGhZlbzB0eLF2vWCp1XKRHeKO7frfy
         qqLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.169 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-qt1-f169.google.com (mail-qt1-f169.google.com. [209.85.160.169])
        by gmr-mx.google.com with ESMTPS id a19-20020a056870b15300b00144a469b41dsi2446871oal.4.2023.01.01.04.24.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 01 Jan 2023 04:24:31 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.169 as permitted sender) client-ip=209.85.160.169;
Received: by mail-qt1-f169.google.com with SMTP id j16so20579055qtv.4
        for <kasan-dev@googlegroups.com>; Sun, 01 Jan 2023 04:24:31 -0800 (PST)
X-Received: by 2002:ac8:47cf:0:b0:3a9:80a5:4dea with SMTP id d15-20020ac847cf000000b003a980a54deamr56844791qtr.30.1672575871160;
        Sun, 01 Jan 2023 04:24:31 -0800 (PST)
Received: from mail-yb1-f176.google.com (mail-yb1-f176.google.com. [209.85.219.176])
        by smtp.gmail.com with ESMTPSA id n23-20020ac86757000000b003a826e25bc4sm15911813qtp.64.2023.01.01.04.24.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 01 Jan 2023 04:24:30 -0800 (PST)
Received: by mail-yb1-f176.google.com with SMTP id 186so27877201ybe.8
        for <kasan-dev@googlegroups.com>; Sun, 01 Jan 2023 04:24:30 -0800 (PST)
X-Received: by 2002:a25:d103:0:b0:75d:3ecb:1967 with SMTP id
 i3-20020a25d103000000b0075d3ecb1967mr3169037ybg.604.1672575870549; Sun, 01
 Jan 2023 04:24:30 -0800 (PST)
MIME-Version: 1.0
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org> <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <397291cd-4953-8b47-6021-228c9eb38361@landley.net>
In-Reply-To: <397291cd-4953-8b47-6021-228c9eb38361@landley.net>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Sun, 1 Jan 2023 13:24:19 +0100
X-Gmail-Original-Message-ID: <CAMuHMdVX4Yz-zHvnwB0oCuLfiNAiEsSupcyjfeH+1oKTfQKC9A@mail.gmail.com>
Message-ID: <CAMuHMdVX4Yz-zHvnwB0oCuLfiNAiEsSupcyjfeH+1oKTfQKC9A@mail.gmail.com>
Subject: Re: Build regressions/improvements in v6.2-rc1
To: Rob Landley <rob@landley.net>
Cc: linux-kernel@vger.kernel.org, linux-media@vger.kernel.org, 
	kasan-dev@googlegroups.com, Linux-sh list <linux-sh@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.169
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

Hi Rob,

On Sun, Jan 1, 2023 at 2:22 AM Rob Landley <rob@landley.net> wrote:
> On 12/27/22 02:35, Geert Uytterhoeven wrote:
> > sh4-gcc11/sh-allmodconfig (ICE = internal compiler error)
>
> What's your actual test config here? Because when I try make ARCH=sh
> allmodconfig; make ARCH=sh it dies in arch/sh/kernel/cpu/sh2/setup-sh7619.c with:

[re-adding the URL you deleted]

> > [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/ (all 152 configs)

Following to
http://kisskb.ellerman.id.au/kisskb/target/212841/ and
http://kisskb.ellerman.id.au/kisskb/buildresult/14854440/
gives you a page with a link to the config.

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdVX4Yz-zHvnwB0oCuLfiNAiEsSupcyjfeH%2B1oKTfQKC9A%40mail.gmail.com.
