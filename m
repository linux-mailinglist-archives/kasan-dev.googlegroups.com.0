Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGEJ335AKGQEGLL5SBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 49C282611EF
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 15:18:18 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id u128sf15448383ybg.17
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 06:18:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599571097; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xfcu6Gjk5JPPIdsMWBdq7VXJy3I/gQg+XD1XAdmk9zoef4VJTEmYc9l0JBoGgHspGZ
         sbcZA2cnI+Jqo6uZhl88hDXg3PiMjtVO8bEhu+jvFy2Qa00NgCQbuOoOQc8l1lrJnaWN
         0rZPAOwuCdo0Blk5/2hW9GPBTaZJj5emwj9X15ckLFD00BQkRCXLOk9WqZwl1U4un8sF
         gN2Xh0LQuJ3sObVai1xA2resfE7fPQH9bIa1zSm4dvfOts997PX6LeCrNkUMMtd10rD+
         VjZyA6Tagb0bGekAcSchOG+kyL5e+AH4eZ0ktuUZdKL/eyz7RFfW0sqXu7KhqOchNevt
         sZLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3h21NEPeos3cEeh/np6zosvWuIB7UkV+T2y28Mj4vGE=;
        b=BuEyihKERhk/ReibdKKo5qmmxtOAuPL1Ul9FVxXKCNWAzsg8f/LnIhJERD6ErYQVly
         EAjciooHpSgt5wowxR48fOTYQUSyGkfysuJF3XrjD4HkeQ3aNJwG4RxS79gv3c0a69Ga
         cNWSKDs1FX8pERtSu+J6MlNZrLOujlVpwMtigRfoEgEwGbnKE5+os+SY9W7ATgmLdhmG
         3pZzku1iEUFGFSaGvW7byfpzlZ9wzg5reyCU17aeSpl6rPLJdktUCqGrwYM7FqDT9AHL
         7KahmCIUZZ7/mGxI6Rt1h7wzSQYrw5t07Y22CbmfJpOaniPgZInkne6RC84qc4TQoM6p
         zAGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ov/ZXMw/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3h21NEPeos3cEeh/np6zosvWuIB7UkV+T2y28Mj4vGE=;
        b=jH3HbckYiPz4DvldeHFJh8gtUUz26bIsxsfa4JyPUnsU04WWfo5e/mqh3tLtT5FLj/
         DMSaGVgvTnCIP1QrlCpjXWOrGW2rn5vU/kJ9LgTnlMgKhmdg+a85lTn5BnrBmGU2h/Xf
         I8dww88jRkLN4+mHPgppDc0kdO877VEpBefyQwc0digaO48kffhFfbYPZ7P+BfsFZd6b
         mc6FQoT6GST6MhnC8k+Ivit2VRcaxnaxJHq5C4e31hXSCdWDchP54mEokzym8S92HKCM
         w2I+2VcORf78oIQKpKblF+ZXfxsiK1R8pZLXtMmMS49d5jrHSu++whmxp+OBMR1pf+SR
         ArvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3h21NEPeos3cEeh/np6zosvWuIB7UkV+T2y28Mj4vGE=;
        b=ORla5RH991HqAHSJIntc9/uIacevyBF5gMz2Hj4cJNrdVmI4arc0v712oiFhbgKM0u
         PXN74FS+QDlllkQSoWli6isXxWP5OPObqYwpjo7kUU1WxRV/fxwVuJyBrwO5SfKw8Qyp
         zrk6Kl4zDf1HskKEWATSwVcS7xUNvCAFRM8p0UoKiNSbLkNQdBeGGRZR6g6xmO7OhpzG
         FjO3bmhDxbuAZV6v+qWCjFl0Z1TXzaTGkUPD7WFn27hqzZydTh6nCw9E7mUX9IsAOUup
         0Qd+Khv5Ydi5pXj+WCbOFXCXq1XQoIIlvHZXUukL5UsNqkZKh0oWYgWBrehQl/NE2KAy
         ckhg==
X-Gm-Message-State: AOAM532m3ACHGdwxfqhm+VkFnPIAK7eCNggc7ddkebVdwXvoR5zT/tyw
	7J/NKGnQ8GbItl8e3Alhmgo=
X-Google-Smtp-Source: ABdhPJzg9kNdbf+all4q9Yu+EUOUeSeyXVpJUHaLEN7nJwTTJ0QahitqmmKn0D5s9KOINdOGdouUMA==
X-Received: by 2002:a25:cc14:: with SMTP id l20mr30335325ybf.110.1599571097060;
        Tue, 08 Sep 2020 06:18:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4055:: with SMTP id n82ls4041654yba.4.gmail; Tue, 08 Sep
 2020 06:18:16 -0700 (PDT)
X-Received: by 2002:a25:a081:: with SMTP id y1mr34717253ybh.370.1599571096661;
        Tue, 08 Sep 2020 06:18:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599571096; cv=none;
        d=google.com; s=arc-20160816;
        b=CM4GfEjlJTxfzkK/D5tGqIwSJdg3O9iDm0faOSZict9neDg2nbJkHWjutV+lWfJQeR
         VvYyGnUczlOHiVzxymYx453HuXn1S+USjNij05mYImg4iy9vZDKXyb9I8UpcPgU/IjBa
         n9iJbk/xMb89961B2EBJfAbXBIX/PPMpIp+WS5Uwb13oRF8Qbc0HJ+iAiLQpsFxyPrH4
         LLKIEQ+SjBn4OabYqvFw85TbC7v04IOzPzRq6PslJhasLqI8ZNZc4BZoaLaPeYPg2oJF
         PzI5OfUHzTv8CWQ8dQ4MDj61hVe1pknZegwGUtY1f8rrzNwh3i+lNKantHfEokCzTB1f
         j5ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0vIgYTSyDPV3iR6+cw+LdVUS1ZrYeuTmFBotSM5CblM=;
        b=rvrcRR1STTWCDdbgYlcQfMSGhKOLFUEnQG6w4zLbjXiIEBHqBd1pmkoSiymGsB2Mac
         ShLm7K93maQsU0sHwIuXfCfTutxYAD6qWH2XM0VTh3A+euY6p3J5W7DLhT/kVsPp/Q+R
         80yebCPa9RXSqG3SJeDp5vPX2ecqc2OX2VtFDtKKMc3d1MKR9/4z/SaeqmKk+GYlxLvV
         XgXENdjAHJMeRoNFssX3w5rG3oaXjgaoSRNQdCx5YUGtRLgsRQ5QdG4WFZ/50pbHUN5w
         VqZj8XSCk6bopw/vEt8vAt4YIewFpe6PbS8G3ZtiVVi3OFrt8WR5CSzyc3WtQrsRgk0v
         GhDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ov/ZXMw/";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id r7si1500614ybk.5.2020.09.08.06.18.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 06:18:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id k15so10909993pfc.12
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 06:18:16 -0700 (PDT)
X-Received: by 2002:a17:902:988f:: with SMTP id s15mr23932254plp.26.1599571095681;
 Tue, 08 Sep 2020 06:18:15 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia>
In-Reply-To: <20200827104033.GF29264@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 15:18:04 +0200
Message-ID: <CAAeHK+x_B+R3VcXndaQ=rwOExyQeFZEKZX-33oStiDFu1qePyg@mail.gmail.com>
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ov/ZXMw/";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Aug 27, 2020 at 12:40 PM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> > index 152d74f2cc9c..6880ddaa5144 100644
> > --- a/arch/arm64/mm/proc.S
> > +++ b/arch/arm64/mm/proc.S
> > @@ -38,7 +38,7 @@
> >  /* PTWs cacheable, inner/outer WBWA */
> >  #define TCR_CACHE_FLAGS      TCR_IRGN_WBWA | TCR_ORGN_WBWA
> >
> > -#ifdef CONFIG_KASAN_SW_TAGS
> > +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> >  #define TCR_KASAN_FLAGS TCR_TBI1
> >  #else
> >  #define TCR_KASAN_FLAGS 0
>
> I prefer to turn TBI1 on only if MTE is present. So on top of the v8
> user series, just do this in __cpu_setup.

Started working on this, but realized that I don't understand what
exactly is suggested here. TCR_KASAN_FLAGS are used in __cpu_setup(),
so this already happens in __cpu_setup().

Do you mean that TBI1 should be enabled when CONFIG_ARM64_MTE is
enabled, but CONFIG_KASAN_HW_TAGS is disabled?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx_B%2BR3VcXndaQ%3DrwOExyQeFZEKZX-33oStiDFu1qePyg%40mail.gmail.com.
