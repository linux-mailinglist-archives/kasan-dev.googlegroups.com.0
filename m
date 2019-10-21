Return-Path: <kasan-dev+bncBCMIZB7QWENRBE4XW7WQKGQEEU2FR7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C00A6DF10A
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 17:15:32 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id y2sf8744150plk.19
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 08:15:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571670931; cv=pass;
        d=google.com; s=arc-20160816;
        b=Akhf19uXihsCiADpLDzBMWJU1+BXiToMvRP9kjERY7ND4QoLOtXpyoK/np8NhDpZZf
         wD4pKepaYr7w0MNE0tr4eut1Hw3thGOZBpFxKgPrhdd5fOBtcgDAXgDoZqROo3YbnBrH
         vPMpbOScONiJSP/LPWRnAXxXkhVxPAoN7AUDTBehgiZWZU/6dfLYspWEDldbp+4kjigP
         wSGMkObH5ANSisCrDUz/34rurZlGz3Al7HRQaMPsVP01gl/hOfN1T81BAn1I6ul3eMJS
         jBmswPK+/dqygHwI1f2gBFxKwmlFguaiK/bHOVmaSqj3Bj1181wdaGJGcY6FlnEV2QhG
         E6CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JGq4Tmh6oeViG2G6J0T2XTVs1DXBUf6py0DJhayTo1E=;
        b=TvvsuAVk3CrHO5fxo7Hz/ZJJPpcfNhUGGv/7aOiV0Yo+sczjby3KqzWmO+PBiw++Uw
         /H3j0hmmyXUCOLtE8iQm0aqR21C5jQfcDxr92lJtaHLsWJ3HV2lgfJjMlkX6pSnrtM77
         BbgaG1tJL4KgjFaIKjigNa5+50ap7Crg+qEDTzWBF1oMf2oK8GKH7ge8MR49fbjeLSaY
         HaXTkOdt3PzP4jfP39NDtbDmUk6uS1zom5W1TqWwvNObDaEnEWsJR0RyOdRjF7NWt/ns
         RAZDhJ60PfCMh442XphG955I49jdBu11uUBO4HXB8T8B2x+L4fdKLl4/+YmvIJk/N1lq
         +wMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g2j1B98P;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JGq4Tmh6oeViG2G6J0T2XTVs1DXBUf6py0DJhayTo1E=;
        b=mgorkexWmVicMWTCvL5FK1PIxkCNzz4vCqSjwfHbX6COvehOsYRuKNFMuNyuuZIGuu
         qoG/hP4VqgRamIgaAx8QYxbYubuLF7cytv+p0vzMoWVUcYO5OBOFRXdp6DNTQjiAwx0j
         MzW4q8k++S4xBHGjVSQLvWOK+PAPSYm9qKddVL4QkXH9FxwkFwQcpr1TowcdBc4DqAxQ
         PXcLoDA462z0+V2T4OunmUqafHWYwOZWjjBHIonYcK2Aqvqe/IWgNb1AXPS7SqJF0ZqB
         yt3/IYBeOmr05fRVpALraBWp2k7Zevof63YnNhfQgDytbcUixoiWLWEOQBvOhLkcRUlB
         DTXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JGq4Tmh6oeViG2G6J0T2XTVs1DXBUf6py0DJhayTo1E=;
        b=hsz/lU5uU3itHWJmg1L8By7Y3K9Wezfqw6HmpHM4iLkt4IZfYB35sm7sNJUotMpKvJ
         MG5rRBiBSQ1KZWszVyv+9TVqMKQRICSyu+lYPIhL5fJuLXzSso0pG8brM1+Nug50UdpL
         MB3dZ69NVyvmzpOtDsEWgGb3u9g+SeL98Swiyg1bw+eHlYU854fBYMbAXRPxnnIZTWPR
         gRQatMZTbBppZvYifwo0DtsBBMX537i496qKhCf54DiCf9vhXClTzVHzdfCY1DG5XMlT
         hwLXmG5HaDjuITXIeM8n2d+W+c0OP/JgenMVKPF7UyGsn6OwN05MIoWVAd7NiHfkolCj
         mq/A==
X-Gm-Message-State: APjAAAWXOxZJcZ4M0JEhnWn6x5GvwzZpXQFT2qh9MyEagMw+JDoeDwDm
	1QEj6TrIaEBVWkZpj26MzpA=
X-Google-Smtp-Source: APXvYqzBNIHPnS6F/Bj9J51IeF+Cxc35DMcqd1AFzdr/41csh7bRs6QIiUdT0wPGyrVIm/POYLsmRw==
X-Received: by 2002:a17:90a:9a92:: with SMTP id e18mr30110622pjp.87.1571670931395;
        Mon, 21 Oct 2019 08:15:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5107:: with SMTP id f7ls3939989pfb.2.gmail; Mon, 21 Oct
 2019 08:15:30 -0700 (PDT)
X-Received: by 2002:a63:c445:: with SMTP id m5mr5827162pgg.211.1571670930592;
        Mon, 21 Oct 2019 08:15:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571670930; cv=none;
        d=google.com; s=arc-20160816;
        b=jMfoQXszQAYLZHobe6SbkNd0fp8vtrBksbU8If1TVG4kgM/q4WeTDdEVRhM120HRxX
         7pvaawGSbL40RhmnYRkBncYQowJR8Y4ydgdptadaOIVfVW989LelZ9pAVvPlPcR/deo+
         +C/tBvN7vq9d6X0H0eggsXjowl2nDl5czg7A9AWadydYE5/aSsIP1IN5my5CXR7ZJKww
         tdpdiTBwLA4EWn0nKAIoYw9TUw3+QHpHXs/OWVz20+TVATZDVj6V7vQCOBytglMblMcM
         LmhMZx2bl+BmBUoLwoRSRb4kYEIUF60Y0BtDJWtcDSofDRwDDLDdXCGbVMN9D3/R9gXv
         aCEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ACBxtsWVb2OWpcnIOOtAMcXYGAqFOpXwv6cGgopBFYM=;
        b=oMjI9GJTJHgSatsOLJcewgB6bze99gluRfGndD5UjtdLST6Fy4PzaQtepVLiX30YCx
         HKFY+PkRt+uiAWx6e7pUTZ8BI5iMJMnrSRMcnLx0rbuh2MZQS4VAjAwSocXC57BV7BgD
         XRVK7R0yobQ3mqiDN3JeQNP8A2d3wwutLpHo3v5Q8lK++XTDKVPA7C/fMG1Bg4fS22Yg
         eRaMWEBQGcoQab7LV4AXpFek5N3Sk4j1+oncPxhCPHmIFQHnsLqf6cziB/IXa+M/V/af
         E2968KbhFlqftrysp7/AkY5IBiCBwi2Vkkml3ukNXQmwFCDPUdLAJp9YfHHTNT1lqMf1
         7lLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g2j1B98P;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id o23si678617pjt.2.2019.10.21.08.15.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2019 08:15:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id w14so21523520qto.9
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2019 08:15:30 -0700 (PDT)
X-Received: by 2002:aed:24af:: with SMTP id t44mr4231217qtc.57.1571670929269;
 Mon, 21 Oct 2019 08:15:29 -0700 (PDT)
MIME-Version: 1.0
References: <20191017141305.146193-1-elver@google.com> <20191017141305.146193-3-elver@google.com>
In-Reply-To: <20191017141305.146193-3-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Oct 2019 17:15:18 +0200
Message-ID: <CACT4Y+b9VYz0wji085hvg3ZMMv6FR_WGc_NcEZETSOvME6hYOQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/8] objtool, kcsan: Add KCSAN runtime functions to whitelist
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, 
	Jade Alglave <j.alglave@ucl.ac.uk>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Luc Maranget <luc.maranget@inria.fr>, Mark Rutland <mark.rutland@arm.com>, 
	Nicholas Piggin <npiggin@gmail.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	"open list:KERNEL BUILD + fi..." <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g2j1B98P;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Oct 17, 2019 at 4:13 PM Marco Elver <elver@google.com> wrote:
>
> This patch adds KCSAN runtime functions to the objtool whitelist.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  tools/objtool/check.c | 17 +++++++++++++++++
>  1 file changed, 17 insertions(+)
>
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index 044c9a3cb247..d1acc867b43c 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -466,6 +466,23 @@ static const char *uaccess_safe_builtin[] = {
>         "__asan_report_store4_noabort",
>         "__asan_report_store8_noabort",
>         "__asan_report_store16_noabort",
> +       /* KCSAN */
> +       "__kcsan_check_watchpoint",
> +       "__kcsan_setup_watchpoint",
> +       /* KCSAN/TSAN out-of-line */

There is no TSAN in-line instrumentation.

> +       "__tsan_func_entry",
> +       "__tsan_func_exit",
> +       "__tsan_read_range",

There is also __tsan_write_range(), right? Isn't it safer to add it right away?

> +       "__tsan_read1",
> +       "__tsan_read2",
> +       "__tsan_read4",
> +       "__tsan_read8",
> +       "__tsan_read16",
> +       "__tsan_write1",
> +       "__tsan_write2",
> +       "__tsan_write4",
> +       "__tsan_write8",
> +       "__tsan_write16",
>         /* KCOV */
>         "write_comp_data",
>         "__sanitizer_cov_trace_pc",
> --
> 2.23.0.866.gb869b98d4c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb9VYz0wji085hvg3ZMMv6FR_WGc_NcEZETSOvME6hYOQ%40mail.gmail.com.
