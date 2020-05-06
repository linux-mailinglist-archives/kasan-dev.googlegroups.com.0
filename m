Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBXVBZH2QKGQEVQUK5ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AB671C67B5
	for <lists+kasan-dev@lfdr.de>; Wed,  6 May 2020 07:53:35 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id 7sf483694ooi.20
        for <lists+kasan-dev@lfdr.de>; Tue, 05 May 2020 22:53:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1588744414; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gh2WqAwcw5VV0QlevANperAk16K97NHtb2KQ0XX6/EA20UnRomdKjturWbeRx0eEKh
         Voj7vEGJXYa5RyvtNuhSJQVe85W7y1lK9MRW+Vo4HT02g3BONPBAyeufKCxXjTITP3rb
         M3fpheQ7CEhg+GhOZgDFGI03E9TEE4ThBZwnvrL205i6CPRJoX029QwteSR42Zm4bA8r
         NO+ufOCBuKA+/TGhyKDhNi0m8oRVeTVfBJHbfLqqyuHNZipCxlA5JZMPjFfM0AjRBZpD
         yvrqDqfj7MX9UCCErZPPsfXMqI1F7w9CabS7Om8e7+7M7G3G/gTKaglVl4zfWXSoCwfB
         kz1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=NUGy1BEIIW4TVRpuA2ngEOFMkB2jvSjiTeRkBo87620=;
        b=Sjis9DBJIO4er9ShftKBYlKD9cRLPinkveq02PzkFNL3I736wjZrVfEhKT0zjfzily
         ll4gYXsBLqRFblkcYHV/O9hdufWdzHmZBnlnVTT20n2H+SowQOPG7L73aOmIgACYbfzZ
         gBwE9BX39amFHlTKKfGU8e4ocbatASsW6M9LXKdvKB8+L8OzJ+MN5TLk7CFJdzPQ2USS
         JdUd3OLyaYI4oDHbmdF4UpG3e7yK1NOvos7cHZ9Cugwbt7bdojVxP3Ppvoh6IAxcrQtr
         g/uj3TI6WBawd4wCrmpkjlc+kxHxACo1j0ro++Cijx5360jptT5p5gfd9p3BeyDEOOp6
         LjoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="bHT6W/fW";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NUGy1BEIIW4TVRpuA2ngEOFMkB2jvSjiTeRkBo87620=;
        b=kVvPCjqvgMZemjZih8kMP/E8qhcve9Da90gJojsqPGcWx/Zry1wswuZYtsQH8RmfS8
         OuVejuHiI78xAoQYAzoxqdFNEt3zDui4kMWb6AjIA4Q7T2fWq4P/3DHPML4NSm2Zm8uG
         5NJgG+TFLEwMeNNFTHy0/vJHkJOwxfTak5MFvo0VrQYVyVuM2xgposc6aAsmKCN1Znrn
         hFaJg29raSCPuutDPd7VD/u5fSw7nCuHyrHxya7xxs1tkyU8tUFT65Msd9kk6TYXqpbm
         YtV9g/ghFLX2EUt//y45ygAncD5cHyqA5H3JFg4S2zBCcFf6zFIe7OTxyAtv8TaIl91I
         KGbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NUGy1BEIIW4TVRpuA2ngEOFMkB2jvSjiTeRkBo87620=;
        b=LC/TqBhUeBl0R7f60kEWmBK/iKikaI5bRQn+9MUtXj49q49FqPkOVhMmX8rk8+ncuI
         1FhQ1eytIXsCXYGBr5A1WQuEcKzIJ5NH+xvj2prB6gBC0kPve4E5GZTcu/2kluCGmxp6
         f0Jdm63TpT1u+KdxAhRzudL+eoZ/azfClM3RDEKM3dRh3NSmvuLWqNwfqQdWrM2DtOtk
         /wTUy/LWXC18rGlxZx/aZsaxEc6ZmX7JJsuIQmFpNudA9xOgK7wIHnnB6sySD2mAonMd
         Z9OrjzJkb2v5jwJYTT1MCliXzQHD+YjsmdPucQHbl+WRG1X3NPtrqVPEL6AY9ox+oWMR
         60Jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYD4NAFm6luCfpuUPK0tOS29f87nvWWFJex9dzU2bqfAmnKhEhV
	uBUFdt6GjxdiwSDw1GaGhMY=
X-Google-Smtp-Source: APiQypKKkxTZ8og2hGvG/TQgTKVYw9Fup5pJisOP5SO/f64vtt9aiZeruabkZkVE4ZJM755nUmn2jg==
X-Received: by 2002:aca:d707:: with SMTP id o7mr1613595oig.126.1588744414412;
        Tue, 05 May 2020 22:53:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:dcc4:: with SMTP id h4ls57930oou.4.gmail; Tue, 05 May
 2020 22:53:34 -0700 (PDT)
X-Received: by 2002:a4a:5d42:: with SMTP id w63mr5927180ooa.49.1588744414029;
        Tue, 05 May 2020 22:53:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1588744414; cv=none;
        d=google.com; s=arc-20160816;
        b=Pl8wUGLlHDktJMfp5JI5s+PXyD3bHUCl0RXva/5IuL71VEuRh17r7k5gLQfBbZ2YwG
         n9SBJvV+OZBolE24s19pLLDuY/XohxOpADkVcKOTB8vVbGs36jLr/3h4Rm9CU3Az6/qu
         b1a4Gb7aHPtbMXxN5yZW/fJ/8QmBEEuGLH4j553gtpx8EP/GjtrVwKDUpbLCCdIh2HL7
         0gMXgXRN5nV5dqOlbrnKHZ4sJwxYe5hsY+YF9SzqgRwYU+00JfM0eN6pQoE4+s0CEIl5
         maospLCByoXDQGnOGFZl1iBmIjiZ0OpaNAdfI2Mkfaw482DuEo72MMDv8tA3MHRbD+f8
         QyAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=22ofnai8Kmb8nUlZsIXdX+pSRFQQCaWUWDTVletlIn8=;
        b=xDfHuGcqz3wjsVxr675dFpLNR+QGFa6jR2ujXXSXJtcC/0IOds8RlNc4qchbRqkm0Y
         rGs1AMoU+3VP/Kc9a/XKZUiq4tvXo9+vmfEVl+GZFS86/nGFLXmg4hVdkwIBScvB/kpl
         OGHbKYknYArrslt9x+Cd+v44Xgu421MmwiHENENjAm2YourHcaAAAv3bbzNT01VasX3x
         IIjkVTVIAUFxVlRRCHVBsLMSD0Cr1hk1mtJUkQAdp03WTK2i8RocHGUxNOwyrE7GixDX
         JECLakQetye8Lpr+A/fvSUOg2dWZn5iGDuksGl/D0vLVGJY4hp2oK85c5lyYwUxjuC4E
         UkRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="bHT6W/fW";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id i22si109535oib.2.2020.05.05.22.53.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 May 2020 22:53:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id b6so784680qkh.11
        for <kasan-dev@googlegroups.com>; Tue, 05 May 2020 22:53:33 -0700 (PDT)
X-Received: by 2002:a05:620a:a12:: with SMTP id i18mr6804658qka.316.1588744413624;
        Tue, 05 May 2020 22:53:33 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id p31sm706132qtf.11.2020.05.05.22.53.32
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 May 2020 22:53:33 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH 0/3] kasan: memorize and print call_rcu stack
Date: Wed, 6 May 2020 01:53:31 -0400
Message-Id: <2BF68E83-4611-48B2-A57F-196236399219@lca.pw>
References: <20200506051853.14380-1-walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 "Paul E . McKenney" <paulmck@kernel.org>,
 Josh Triplett <josh@joshtriplett.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>,
 Joel Fernandes <joel@joelfernandes.org>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org,
 wsd_upstream <wsd_upstream@mediatek.com>,
 linux-mediatek@lists.infradead.org
In-Reply-To: <20200506051853.14380-1-walter-zh.wu@mediatek.com>
To: Walter Wu <walter-zh.wu@mediatek.com>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b="bHT6W/fW";       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On May 6, 2020, at 1:19 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote:
>=20
> This patchset improves KASAN reports by making them to have
> call_rcu() call stack information. It is helpful for programmers
> to solve use-after-free or double-free memory issue.
>=20
> The KASAN report was as follows(cleaned up slightly):
>=20
> BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
>=20
> Freed by task 0:
> save_stack+0x24/0x50
> __kasan_slab_free+0x110/0x178
> kasan_slab_free+0x10/0x18
> kfree+0x98/0x270
> kasan_rcu_reclaim+0x1c/0x60
> rcu_core+0x8b4/0x10f8
> rcu_core_si+0xc/0x18
> efi_header_end+0x238/0xa6c
>=20
> First call_rcu() call stack:
> save_stack+0x24/0x50
> kasan_record_callrcu+0xc8/0xd8
> call_rcu+0x190/0x580
> kasan_rcu_uaf+0x1d8/0x278
>=20
> Last call_rcu() call stack:
> (stack is not available)
>=20
>=20
> Add new CONFIG option to record first and last call_rcu() call stack
> and KASAN report prints two call_rcu() call stack.
>=20
> This option doesn't increase the cost of memory consumption. It is
> only suitable for generic KASAN.

I don=E2=80=99t understand why this needs to be a Kconfig option at all. If=
 call_rcu() stacks are useful in general, then just always gather those inf=
ormation. How do developers judge if they need to select this option or not=
?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2BF68E83-4611-48B2-A57F-196236399219%40lca.pw.
