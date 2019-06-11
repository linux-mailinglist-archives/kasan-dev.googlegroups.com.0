Return-Path: <kasan-dev+bncBCMIZB7QWENRBK6V7XTQKGQEQ2WVPII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A0D23C657
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 10:47:41 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id z10sf8698389pgf.15
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2019 01:47:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560242859; cv=pass;
        d=google.com; s=arc-20160816;
        b=gJ9PYVjgLxSNBrrAbCzAlkhoy/ZYJ5TPzN6TIBlwWqOdulljLav7mXonQLYF7Xb+Ui
         +GcrH75UOCP4p6O0Ny85HaJ9NMC3inROO7bqdEzIOfMZGoUOgdTfKow6fN1IgOXMranY
         ZR14gs5D3yRzUPwo0OIHdwGvxPgPxx94JYHeZuRhEiZisrVzAM/yEdQqxHn/YUyaoFiO
         VBToZJ9Ivx0cdpXIQPGCW0IMX908CgjuSrKmUv8MAnyBmNbdRilLEg+0h8nNx1DnNQf5
         ZEmb0j9WfYMs6CNJuQQEe5vaYnIX1v4A9u9xTHP2UCN8V7YoBHimoGdyG0ehP7KPv9TP
         yYaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gVbJSeoIyfAQBi+y3WwN44SJxxD9gCZNthaMxki2GD8=;
        b=KAlU/YfKQLMji7imOu5jZyJQagTJvH0MM7Z8Y4RQnDnj+K6gdb+gCvhmIF0hGw4Hpm
         EV9BErFrkCsmvClyhN5+7AT9LV4csV1VxF4XvktgBLR4aC2sM+PzwdRYEDtKF/yq/YbS
         xupM5uLualzJ40mU7FlmKR2N/4yJZL7uKCcuIeFZgH9Q+kHja81tIR57w02uZfXrYn/Q
         jTsPBf+Nj/miIcMgjJ1Y+dcvG73wQvPLXe2JhDMAf+PxizHxCQTuy2UVXUdluWJhJEuz
         biTMyLA7LjeyW7wFK92SUD4N7LmVXS3nGC7p/z3iAft2tUG4/9LlvFv8agNvRdJyOmcu
         ms7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=reminkYh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gVbJSeoIyfAQBi+y3WwN44SJxxD9gCZNthaMxki2GD8=;
        b=nlVtqDNF8M4McrojjDw0+GCk95s8QIExe4ZUz9xeR/vXOOruLqEIsc/9OOF9Ax5VbZ
         nCACKScnhEt/WaJIUXY1nsA4U/i5qZKvBWECWgcpNpCv9va4lI2R3yMiAJnRdXl5Mw+b
         nGcXYzXYhAE9Iapi8xLZWtc3E9O4XacRHuL8nEx8qrNgpN725HkzbVx/Ma4sddPmOWa+
         0iudI5o5ey2JpJZZYdQceuVGwHDxyapNQa/gOAy/qp3aAizpS0hsInsxkF0NMnVKtaNe
         GcaUW6+Fey2L+zmXiFPKQO7NcIpDDwYoCu78XqG16qf9rjKGHGIcLeA26owRrA9YQNUW
         7NcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gVbJSeoIyfAQBi+y3WwN44SJxxD9gCZNthaMxki2GD8=;
        b=KXvxUlI/XZfgg2inEK8EMOUKBT+8XMW8Rq2mPytKJQt3z6H2IsSM17ZHC7siUlGIk/
         FVQYEa74QMJbNq/vQUHHuVGZusgBUnn8TcV39gCT/avkNgtP/mMQFPx9r53A7BIN/ZZl
         9eQAOd9guRhOZjZ77rNzyFj7UpZZU7iHAq5SwTBF5oqs4BQWO4Iq5kEM3pMcGU7fj+ze
         RImgGk0PM7J1NfqRqKr8C9QONPB6tHNpTV0UlpgvyTPRR2yAUigw8k7PkU8jmdPUVHuo
         ysNhdnFjerSOQfPuzNLPdAFt9faKxzkSewiHjTodTEGUXx32VDmmsdsZrA0WpTHpYV+Q
         eZnw==
X-Gm-Message-State: APjAAAWnnNoQffdgmEWE2MtB5wG+6Ws/9FVFxR5E6ufdGMH12OoFQT4V
	twURCiu4W/OKbftBNsBPVNI=
X-Google-Smtp-Source: APXvYqzLf6J3dTaYYa7NuIn/hpTQ1LhKVe2I2WGtEUKvVXNbeRwut+gKFSaUbwpHRosUoh5cwAskcw==
X-Received: by 2002:a63:e018:: with SMTP id e24mr19182219pgh.361.1560242859371;
        Tue, 11 Jun 2019 01:47:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8115:: with SMTP id b21ls3084455pfi.12.gmail; Tue, 11
 Jun 2019 01:47:39 -0700 (PDT)
X-Received: by 2002:a62:36c1:: with SMTP id d184mr81125501pfa.49.1560242859085;
        Tue, 11 Jun 2019 01:47:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560242859; cv=none;
        d=google.com; s=arc-20160816;
        b=Lc/TII4+p4LgAPvUOTkf1F24Jo8FNs8fT0Qer2yQFi5Umg9iE8drgmXB77xkvhPh8G
         VXas52jFT8CYV4Vn0TX5TGVHVYn81/ZYNCbGC2kc/w+eo1eHbeY9/9vNbKw9dIE41j2k
         r4grsWNwxMdtkWWznv3c+tg/VJBru7N67HXxMDtJGUQ8mnha6zmwG+GBOA6zc/g7lnF8
         dJJIeIogqfZX7rv5Gx2SKcm1HvM7xa5YZu1gxjk2EW8LhSsHF1npUZjVJ8ZGVQKGNxAM
         mXdDTv7OmSOR2R9HdywmmFwcrvNAtWaWKG75zGS80I4b87HEuIg4RVUaeZClKTf1I8Tf
         BGag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VF1kGVddFpIAC2XDRsCvaPTsWd3oiEHLMIFP7bJNfAA=;
        b=h+uNMFUGOM0Rm+EqM4RMUiQ88WVSfxirDBZoy9npdxkkMDmpdHamh6aAAV3U++cMpM
         YHrRN6fGTqGB/TtjmYq+HHtBQnD6gR0DWrIgRUf0bSC0gB06+y3+1kOAdpjiI68TKKew
         Pqj2mN292VPhPQV+rhGHm1QFh6oKyoiCh5n9RFUWtEdlwPaiBCbjcZjCYva4VND1amT2
         aYa0LeGQM1gaQ7PCp2TdgVSR4PnDO2l2WFrIhEUWwss83gApwa1gpKxh1c/WS2PPIyNo
         uy7Uif5TYf/5zKGvKikjMlt/83tqwty8sWe7Ay3CX+piku2px3FtFxvfYw9Bc4shjyye
         PzRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=reminkYh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-it1-x12b.google.com (mail-it1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id g18si538734plo.3.2019.06.11.01.47.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Jun 2019 01:47:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-it1-x12b.google.com with SMTP id m138so3543723ita.4
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2019 01:47:39 -0700 (PDT)
X-Received: by 2002:a24:4417:: with SMTP id o23mr18107239ita.88.1560242858490;
 Tue, 11 Jun 2019 01:47:38 -0700 (PDT)
MIME-Version: 1.0
References: <1559651172-28989-1-git-send-email-walter-zh.wu@mediatek.com>
 <CACT4Y+Y9_85YB8CCwmKerDWc45Z00hMd6Pc-STEbr0cmYSqnoA@mail.gmail.com>
 <1560151690.20384.3.camel@mtksdccf07> <CACT4Y+aetKEM9UkfSoVf8EaDNTD40mEF0xyaRiuw=DPEaGpTkQ@mail.gmail.com>
 <1560236742.4832.34.camel@mtksdccf07>
In-Reply-To: <1560236742.4832.34.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Jun 2019 10:47:27 +0200
Message-ID: <CACT4Y+YNG0OGT+mCEms+=SYWA=9R3MmBzr8e3QsNNdQvHNt9Fg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, 
	"Jason A. Donenfeld" <Jason@zx2c4.com>, =?UTF-8?B?TWlsZXMgQ2hlbiAo6Zmz5rCR5qi6KQ==?= <Miles.Chen@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=reminkYh;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12b
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

On Tue, Jun 11, 2019 at 9:05 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Mon, 2019-06-10 at 13:46 +0200, Dmitry Vyukov wrote:
> > On Mon, Jun 10, 2019 at 9:28 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > >
> > > On Fri, 2019-06-07 at 21:18 +0800, Dmitry Vyukov wrote:
> > > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > > index b40ea104dd36..be0667225b58 100644
> > > > > --- a/include/linux/kasan.h
> > > > > +++ b/include/linux/kasan.h
> > > > > @@ -164,7 +164,11 @@ void kasan_cache_shutdown(struct kmem_cache *cache);
> > > > >
> > > > >  #else /* CONFIG_KASAN_GENERIC */
> > > > >
> > > > > +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > > > > +void kasan_cache_shrink(struct kmem_cache *cache);
> > > > > +#else
> > > >
> > > > Please restructure the code so that we don't duplicate this function
> > > > name 3 times in this header.
> > > >
> > > We have fixed it, Thank you for your reminder.
> > >
> > >
> > > > >  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> > > > > +#endif
> > > > >  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
> > > > >
> > > > >  #endif /* CONFIG_KASAN_GENERIC */
> > > > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > > > index 9950b660e62d..17a4952c5eee 100644
> > > > > --- a/lib/Kconfig.kasan
> > > > > +++ b/lib/Kconfig.kasan
> > > > > @@ -134,6 +134,15 @@ config KASAN_S390_4_LEVEL_PAGING
> > > > >           to 3TB of RAM with KASan enabled). This options allows to force
> > > > >           4-level paging instead.
> > > > >
> > > > > +config KASAN_SW_TAGS_IDENTIFY
> > > > > +       bool "Enable memory corruption idenitfication"
> > > >
> > > > s/idenitfication/identification/
> > > >
> > > I should replace my glasses.
> > >
> > >
> > > > > +       depends on KASAN_SW_TAGS
> > > > > +       help
> > > > > +         Now tag-based KASAN bug report always shows invalid-access error, This
> > > > > +         options can identify it whether it is use-after-free or out-of-bound.
> > > > > +         This will make it easier for programmers to see the memory corruption
> > > > > +         problem.
> > > >
> > > > This description looks like a change description, i.e. it describes
> > > > the current behavior and how it changes. I think code comments should
> > > > not have such, they should describe the current state of the things.
> > > > It should also mention the trade-off, otherwise it raises reasonable
> > > > questions like "why it's not enabled by default?" and "why do I ever
> > > > want to not enable it?".
> > > > I would do something like:
> > > >
> > > > This option enables best-effort identification of bug type
> > > > (use-after-free or out-of-bounds)
> > > > at the cost of increased memory consumption for object quarantine.
> > > >
> > > I totally agree with your comments. Would you think we should try to add the cost?
> > > It may be that it consumes about 1/128th of available memory at full quarantine usage rate.
> >
> > Hi,
> >
> > I don't understand the question. We should not add costs if not
> > necessary. Or you mean why we should add _docs_ regarding the cost? Or
> > what?
> >
> I mean the description of option. Should it add the description for
> memory costs. I see KASAN_SW_TAGS and KASAN_GENERIC options to show the
> memory costs. So We originally think it is possible to add the
> description, if users want to enable it, maybe they want to know its
> memory costs.
>
> If you think it is not necessary, we will not add it.

Full description of memory costs for normal KASAN mode and
KASAN_SW_TAGS should probably go into
Documentation/dev-tools/kasan.rst rather then into config description
because it may be too lengthy.

I mentioned memory costs for this config because otherwise it's
unclear why would one ever want to _not_ enable this option. If it
would only have positive effects, then it should be enabled all the
time and should not be a config option at all.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYNG0OGT%2BmCEms%2B%3DSYWA%3D9R3MmBzr8e3QsNNdQvHNt9Fg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
