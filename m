Return-Path: <kasan-dev+bncBDW2JDUY5AORBW7YXGGQMGQE67VDEHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id DAE7046A935
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:10:52 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id e2-20020ac84142000000b002b4bc4ffc49sf14185638qtm.8
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:10:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638825052; cv=pass;
        d=google.com; s=arc-20160816;
        b=DMU4cgOlPG4G/rN8TE/jg6IuptU5J7oUZiySGvMdj+qVA7KLlnAxzkeuP/vTQVgV6i
         yaydoxJUS/HngVarXqKgTs9+7Qu83RksnlXLa3kP/wXLkQJCKj0Fi30PV72VtRTOHo2v
         WESd0WZCmkndNNwcAAaLsaoUm4VXQkSm5yvcxsLfbPvUSSOtuhHI6aEpb7ip43JAxZzA
         FVaQaVCb6XmV72kYgt4hyvxFCFHBi2wOX9RyS49KErhaH0zjcvaBWP3l7iZrcxe+PIdD
         c8dSjMkHpM/8zoPM5P5H4h6PwKKbGqG7+IB4SzXT5jpPzUiHEjJ49kev6d/jGyppehAU
         Fc+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Vijm3CN5E9DURaiJVSK9YvmhMEggM5uAB5VpWjpx1ds=;
        b=qXNDBeky/iP16SMf3cZcpJJ0vJ+jTQYpsVuMY+iHv3/6ERwj/a8CnYFWL/2p17niEM
         Ox3uahKU3PzgVYjRWs5HV3eHU4sdi7jTmw8r92//ckfGkRx4/0bXJljnYPGtDJqFxjh7
         J1/ZWINk4O+GvD+NEWiaieJ6a/qsKSwUo+77TOCbY4LcpxmmSbaIU+zHG7ZqKHGHD6hh
         Lgb3sZYh95TbxHZJznXrdHqfZgeXzEpdrUyK1iyLDTko9wDwwHhl+cUX5D5Gh1zb3xYl
         CKXIw/hGF2ueCYfszAd0ObhpXoOXfVKqVNL1PzKBY+4ihPLD/bVJpX+vuqSaBFn3L5yz
         ChSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ifoMfxOx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vijm3CN5E9DURaiJVSK9YvmhMEggM5uAB5VpWjpx1ds=;
        b=mY01TCDxdV73reitQwx7fIzYX9nGVdspAQ02KbxhyDJSY2qX0gqWJnAEuGbkfyFxOn
         3gKwPwun7skO8PzNqM5eA5BeFHSHH1gGld4qUoe/3STRL3MRR7k/z2p7oM0CMIpYJfNR
         DVbVXOBibqW2Vd8QMkyTL7dUT91S+wfQLL53u5epo+oocW+jLi+j73NTSl3KiC5yG2cE
         Htz88xewDq4oBwDT7SCHFpy393vOmT5R9vMsMyHdilFf8MfFTft9WLWnl23rNbMaP60c
         SvF15zG9kM7HQbcE8q8ogxTdmVIaWX9H7iErylJ4riWge4EmeGUpNnvCFbcEpoooJDUX
         W0xg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vijm3CN5E9DURaiJVSK9YvmhMEggM5uAB5VpWjpx1ds=;
        b=ah92rFbkwk1re/BNQvbjq0ENKHsdurepZm20XNB+qyJCsd60EbSjcJpcQ6rJG1DmM9
         5GFeWKPcsfePHIMqjKHEmGhuosq0uuh2dAtSB5k4jXRTmWlyU/y+h8Ftkmcoh5bVtZfA
         BFyuYTFcZmlH1nDW5pb/fmbFUFt+swSLyO37fZtAwbVK7Smjhx+NhRW1L7vUt+VpeV6J
         OfH4ic5Hfn+rSukbVrLBtppBitJN+Rc2nquNi0/0E6kJeEYTtlwd3hdlxNp+q9qbyoIJ
         rBHQWWqQr6WsboL+aWt+OqqYcRRBFrTH155kvFjyYmPx8yQDHouDJXpzOwqD6U6n2FcN
         7mCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vijm3CN5E9DURaiJVSK9YvmhMEggM5uAB5VpWjpx1ds=;
        b=SNrF+rZ0Y6XPtNim0TntOSLLe727/4e2bkWefEXfET8RMW+x0rpeY8j8M/BBf43Exa
         7GJpVepnvKFUkpf7IOUHmLMEbWnI/9Dhf6OBvSG4RGmGEXftHMpLJEWECw8wx+XrM5Z+
         t2GKzhjRiSX4MVo7BV2oeDPUsQhjkQYIGpgrOtVRwdcLbp+HIYawlWWWWOZW8H6h3y0S
         M/QOAtyfF8kSwjiAhanOLbAo5TpD0pyAJa1ZI//KAKaJ2kPEkO4y3gHzLd9RJcZrIt31
         NSOIGdPUkh1frsnZHTYyDjZbylwi70lJT5jCW4JzrCLV6luSwYazQtTXUERms3tMA7bG
         noGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mBfPNHSjNZxhsOdC70JI2Q9DmKtsuWel7N2HZlDngIGplh4yc
	0zQxi3DnKY8aYX3i1ANNwC8=
X-Google-Smtp-Source: ABdhPJzklrn/NEQ+J9+u5EIt6mwBXfY6u4/88FWRQjIMsXNr31giiRLjwOU2jr8V/GlEopFSXpSr5Q==
X-Received: by 2002:a37:c20b:: with SMTP id i11mr36949906qkm.300.1638825051930;
        Mon, 06 Dec 2021 13:10:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:28c8:: with SMTP id l8ls9411900qkp.1.gmail; Mon, 06
 Dec 2021 13:10:51 -0800 (PST)
X-Received: by 2002:a37:b306:: with SMTP id c6mr35954204qkf.133.1638825051548;
        Mon, 06 Dec 2021 13:10:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638825051; cv=none;
        d=google.com; s=arc-20160816;
        b=k9DA+gbB4ZqYieeuNqTqnrnHxwZ3BkohJJUsqGidfqVWOKnGOPt5KS/zgnL6vqucFS
         LbFS/GrW5mXL6+94VJpx/2RdCCMg0Nzjh08ImBD/wbWw4WW81i6/QlfHc304rjPkPcej
         REC8PhfypvXB10s6TrWq7nya5+z6Ot3ctibYLl3dBsbvJZNGpgTmlM2FPRMHccloOI0+
         byFzqIEIXXWvCNdM7qAHxoNWtBhp7K3P8CGuARrNGUY+xcgmftji7KQU9sFqZhG4NIFw
         kwn0slLRLe2WkIsOstTKmUThx7KftwulZZ4yTWAgGaAdM76CNW58i/A9BmcBynO18gaV
         5zyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AXJ5BBUpsFZd0oJ0emE1suTXpCCWYGGbU7EtYyrQXzw=;
        b=lR2PgCeAyMQDlPz2s8eYAz78x2/USg0f5kqSKEWAfFPuxRz374rX94KNHIrSbN33c8
         4AIAiytjhk969JP2ZSN80JSBZ52SF+6/ZhZgAy4G7ZSldh3+A0fcmtX3RvBFrSkVh4rW
         SvHeJ+XbwzVXeiYPTnPC1ADX/I3j3MGOtWhROtcblMxqJzfaLpZchZpm/lXp29XggZPy
         xDK452/eDg93v2KAY1yqd69aH7mJDLMxsaBM2WxGflccX6dE63VJreNDH5EHzi83ymX/
         loFuhE34607Tu+192J6Xm/fflVL8/To/FBYKNcLPu/BQ/VOg6lF+JKHTWiJ1C8GBfGhr
         xL4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ifoMfxOx;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2f.google.com (mail-io1-xd2f.google.com. [2607:f8b0:4864:20::d2f])
        by gmr-mx.google.com with ESMTPS id s4si2622293qtc.4.2021.12.06.13.10.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Dec 2021 13:10:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f as permitted sender) client-ip=2607:f8b0:4864:20::d2f;
Received: by mail-io1-xd2f.google.com with SMTP id m9so14670359iop.0
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 13:10:51 -0800 (PST)
X-Received: by 2002:a05:6638:2257:: with SMTP id m23mr45136036jas.17.1638825051087;
 Mon, 06 Dec 2021 13:10:51 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638308023.git.andreyknvl@google.com> <8afdf7eb0bae77d2e94210d689d524580cf5ed9a.1638308023.git.andreyknvl@google.com>
 <YaoQM7xWVKISa5Yb@elver.google.com>
In-Reply-To: <YaoQM7xWVKISa5Yb@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 6 Dec 2021 22:10:40 +0100
Message-ID: <CA+fCnZcv+cAhNY4N5z+=5Pa9sbTXtr4fMU_23OA_-T4nsYqvjQ@mail.gmail.com>
Subject: Re: [PATCH 29/31] kasan, arm64: allow KASAN_VMALLOC with HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ifoMfxOx;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Dec 3, 2021 at 1:40 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 30, 2021 at 11:08PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > vmalloc tagging support for HW_TAGS KASAN is now complete.
> >
> > Allow enabling CONFIG_KASAN_VMALLOC.
> >
> > Also adjust CONFIG_KASAN_VMALLOC description:
> >
> > - Mention HW_TAGS support.
> > - Remove unneeded internal details: they have no place in Kconfig
> >   description and are already explained in the documentation.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  arch/arm64/Kconfig |  3 +--
> >  lib/Kconfig.kasan  | 20 ++++++++++----------
>
> Like in the SW_TAGS case, consider moving the lib/Kconfig.kasan change
> to the final "kasan, vmalloc: add vmalloc support to HW_TAGS" and only
> leave the arm64 in its own patch.

Will do in v2. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcv%2BcAhNY4N5z%2B%3D5Pa9sbTXtr4fMU_23OA_-T4nsYqvjQ%40mail.gmail.com.
