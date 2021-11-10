Return-Path: <kasan-dev+bncBCU73AEHRQBBBR62WCGAMGQEK5M4K7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E46944CAB7
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 21:36:24 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id 100-20020aed30ed000000b002a6b3dc6465sf2940401qtf.13
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 12:36:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636576583; cv=pass;
        d=google.com; s=arc-20160816;
        b=f/xb9Watni9w2DZSPSonffqcaqdMk3Nf7QINlokn9fjovPzdqxuUTErnPiN/e3K/rm
         aw85x5hUccvmco2kYW3PLN/imjKiSwzp5ZDZFEHKJCJlXVfNQeW3wGEyTtbotrEQgCnN
         /VFAzsNGC7W9PgIiKr9E3yuR2RNJKj5znBjpiNpWkl0CJcjZ7TttucJyBEzaVaesNQL8
         NGlRr2sdX7mNJ0avA7Ve1REmiC8OBfnsvVL2J80s+EzDdH78zXu0Anach4JY5zDrTjg6
         Rkey0aG8pDzpk95a1xF+TbbwkYoptRbPIPZUsI2Ebl8pztLb/ayReMjPod21kzVRpO6Y
         jUmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=RLqeaBJs+5p2oj7XJkf54TP3GAVs04VCF1ngK68wIO8=;
        b=rzlsf4VjG9JGnaSQJb3yaiLaJZfc8gS90GODk9aUvu//4YDwRklsYYKtA2j6G9l2vX
         uyPLAxfqWH973M9v2t3O8+H/rOdwJpiTuMxj9zZIYNyfRn+tJVeQZK5Dgfk5dWZhrrst
         Cz1aWYBbuMrCVfbmLRJcFN3psjdcTt9/3/yWOSIFVsK4LF02LjSRLptqTeT3Pp+77+jP
         11TlPhIjgtmYEUXBiQgkFp3Ppoq7Pi/uOf7ES0Hp1zqkK2XOuRqBNpC1dMju4OE3evkM
         bfHP1WIAVFtkILdVDDT9cK906xzPenF1f5Qj09eb8y38qzlwo1ARHn/+XKH7QnrUZRWV
         32wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rvx3=p5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rvX3=P5=goodmis.org=rostedt@kernel.org"
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RLqeaBJs+5p2oj7XJkf54TP3GAVs04VCF1ngK68wIO8=;
        b=Vj4O98+Q8sJuU6rvRZLONnUStUL+UDlO7VMGtsM5atiqyRp9jC4M0V/t2b7Wasf8a2
         S0R+QQFzjBrhFp0SZo6H7qmLJ1faYsammmSPbIe6CaVEHfPQkyImQdo7zsDLEuOWhrb1
         ZcnLVetJ1j5Lk10/JC1pwe8o4YQom0JspYoLZIYIjhvz3BI7wMLd7uKa5DMIEeSvuuUq
         trgSiOK6f6QDduaDzD00G0MyRFMi9ehh01AF3xBDn34VZigBV65QGNyF8WPZnitsK54T
         xY2vR59UNedW/9LfrZSaSV3F0H0UWYxMWXuno+YB23mU7We2acwi+k5pl/2Jtl4UmCuS
         +dgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RLqeaBJs+5p2oj7XJkf54TP3GAVs04VCF1ngK68wIO8=;
        b=xeBkzxIIPxgcpFAu1rEVwbKQI4ubq+i4ER0u5wAfsFyBga1UNFzEfWfgWCYivKcgzO
         Bdwi6upJwokNC3EoZUhBXhrrybsMqiCNxRWi0OlKIHZ2wWfCBJmIIL+AI3xjBEdVjZxX
         wFP8y/X+hRYY6R+3hH6E8VUIXHufqBHRPSCVxsU9vB1xm1F3kjUeSdTtA8Bf1DcgqxmS
         R1ZiWJYqW/lpKL00WffiAeYB+yzdbAIHzrpJEB400sv3oik3Cx+3NewrwMTLuLgYfrXT
         JT+XiT03Iz1aqIQdeDAOuPJTNsXKV/G7erta5tVjQNjGdr0JCB6fM/tE4iCI1vtDemFS
         rYWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PLXcnX/hVnumV4a3IZ67+zCi5Vjvzl1A8wry437B+3167MLag
	d1FT6QBrpio8U8swb8c1eU8=
X-Google-Smtp-Source: ABdhPJxLwM2Jge6SfG1bfH4ztePMllXqyBJCZw7MwP7nQNsvj+6Rg3MN3DmSH19ROUhGfl+UQIQbYQ==
X-Received: by 2002:a05:6214:ccc:: with SMTP id 12mr1536904qvx.8.1636576583478;
        Wed, 10 Nov 2021 12:36:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1712:: with SMTP id az18ls563483qkb.4.gmail; Wed,
 10 Nov 2021 12:36:23 -0800 (PST)
X-Received: by 2002:ae9:eb10:: with SMTP id b16mr1908572qkg.191.1636576582972;
        Wed, 10 Nov 2021 12:36:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636576582; cv=none;
        d=google.com; s=arc-20160816;
        b=uGwoEFCSD4dSjDf19Hi0BYodI+8tXJ5omrBm2TOWIWTPEX2+uTOAyH1MNhnBr/wICr
         4Xjiz372UD5kasoaBYr0U1S7CisxKLMWLarQOBdvxnTpfvXS4LuvLTImiEYZ4zUGwqg0
         HKbodbKr5J7x9POuVYMnDyJCFrfIrphz3HICwIPRKIihVPvr7iSf/B3/sVs26XzOXQjC
         3BFdRQhIOdzgLZQoN1+n3XpuAfc/5WDyCnsm2XhRtGDD3OFfx+Xa9wMmXoHF4x8e3QNi
         JBdYmdShfKmyBTkuOcUQRKsKnzFf7tsuBaTNw8Bsx6dh7DiwWfp8C87qcQ0nk51Bd93b
         ISeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date;
        bh=7QIaMM15WpvIyLvWI4yaCMTBemHDHBACTD1pb94XQ/Q=;
        b=fq4+4C/bVvi4OpfIbHQRwKMbBFMF4qvSQBUXW+H6M2iCEuWyK1OTXkWkh7IedZaRZR
         Cbto29gR5t96ByHfBzDmzXl52OUjdXmIxs3GzGQJbGA/KrnEBYXpcdS+hr8YLVJCNtj6
         7LuIvsRfbLHXbOnjE2xmGxECHHtSCe8avVu9xn6TU4UIXlMr1gS2nf/lxYhOTjB8xjgZ
         pCCuSt14u7/VktEkN1UOXFEEDyDdiuIvrdfoUgj8sKplyoDLhWTYAcjfLCdMb2xF+ZA9
         MMai8X5PiJ3luW8KDyaAAeLQitt0r/FlLjkZuzNJCIzTU+GTQ5WmW4dd4ZP4fn7HFh+u
         T8IQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rvx3=p5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rvX3=P5=goodmis.org=rostedt@kernel.org"
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m5si161739qkp.7.2021.11.10.12.36.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Nov 2021 12:36:22 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=rvx3=p5=goodmis.org=rostedt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gandalf.local.home (cpe-66-24-58-225.stny.res.rr.com [66.24.58.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6E9636101C;
	Wed, 10 Nov 2021 20:36:20 +0000 (UTC)
Date: Wed, 10 Nov 2021 15:36:18 -0500
From: Steven Rostedt <rostedt@goodmis.org>
To: Valentin Schneider <valentin.schneider@arm.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org, Peter Zijlstra
 <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker
 <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>, Marco Elver
 <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Michael Ellerman
 <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Masahiro Yamada <masahiroy@kernel.org>,
 Michal Marek <michal.lkml@markovi.net>, Nick Desaulniers
 <ndesaulniers@google.com>
Subject: Re: [PATCH v2 5/5] ftrace: Use preemption model accessors for trace
 header printout
Message-ID: <20211110153618.5a89eb91@gandalf.local.home>
In-Reply-To: <20211110202448.4054153-6-valentin.schneider@arm.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
	<20211110202448.4054153-6-valentin.schneider@arm.com>
X-Mailer: Claws Mail 3.17.8 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rostedt@goodmis.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=rvx3=p5=goodmis.org=rostedt@kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rvX3=P5=goodmis.org=rostedt@kernel.org"
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

On Wed, 10 Nov 2021 20:24:48 +0000
Valentin Schneider <valentin.schneider@arm.com> wrote:

> Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
> preemption model of the live kernel. Use the newly-introduced accessors
> instead.
> 
> Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
> ---
>  kernel/trace/trace.c | 14 ++++----------
>  1 file changed, 4 insertions(+), 10 deletions(-)

Reviewed-by: Steven Rostedt (VMware) <rostedt@goodmis.org>

-- Steve

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211110153618.5a89eb91%40gandalf.local.home.
