Return-Path: <kasan-dev+bncBDX4HWEMTEBRBB6CTSAAMGQE5ZC4YVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 4BA6F2FBE9C
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 19:12:25 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id y10sf14530108pll.20
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 10:12:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611079944; cv=pass;
        d=google.com; s=arc-20160816;
        b=wzCX6LHe1D30VDOPVWyliGeYn7011EKPEdPaAFLOciaonb90BTjX92c6zeGwAWE8Zz
         RmaBOKEjl259QDHDo+4+LHu7ZeCrubEH60tusKApikEQ8i7qVQSWfrsz8d/KFWp4fs6C
         uC1RvaKh7mTB9wVEmjaLPi0/AE7L9z9Qqq0UH8XDnk4VitWpYOQ+I/6VHZPQki/NU28m
         Fj7iW43r8VA9ep4uKAmJWSGuXyCXpg/7BIEcVLRsz3RAv/pOV96cGxgoMy3h3IdJ6yry
         YHWcl7LHjeHbgfKagWIgoAdeFfg4w4S4QKQWhDs6xkFMNfmJEZ2zBjDxXWdjrAUeuMWa
         WpxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zRwQfBbHOBG1qGi3QjMAkDnw5Ypy6Ma3STWC2cX4ISY=;
        b=AtCbYvZbGEpOJQn2MPMh8KPw/+9XoCfUV5041AqMIBFFHhIE4kCOe69bFpPdK8dmBk
         4eAeQzMtjk5M7rCSlcxv28rm14WX/cljpWxZ2j+rK0dgugx99D0vr8l8Tvgf5blHGGdt
         vHZ1Rn6JH2y9UFnWM66TWOrjsNOrITZhQALx7ueTdbfcrTm2vfRMzZqyTqp66eaCAT8v
         9OMWaFOXU5G2461ewEOpBIq2cGgeWc/S/5ZOG9uB1rdFBPotoZxs6Si2/dqKldb7e2vp
         8vR39CH/CQZaN995REqox5lR8ZU4NaBMxlRJc17qhpyR5iq3NjdxhtaKcfRC4R9/JE5G
         g69Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uTCh6cTU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zRwQfBbHOBG1qGi3QjMAkDnw5Ypy6Ma3STWC2cX4ISY=;
        b=JS/IuF6tQjt80keoIFcAGx1303YLVvXEKe2ec0/zJm0aULApmCvdBcUedPsbIwqwUG
         mwVsJ8ndfRcB/OR/YuxJB+M6DkkTDzCT75PgSznhA/s3fbpkZ7ROcmjiYqlDno8SZhhL
         SSNE8N+oe3eLag64ItUElL4jvREOCd6Bybjpz0b9Kbkuy3A9GW0YosC4TuYmDaydUbSv
         1v6sofC6mfuWaMBmU6asj/MGAEEC1rTjzr3qUHp2KSKzrUrMK6XR2WacpxE4YnHEW8nS
         rnlJJJUIeMdFYqRGDb/mHMqGRJZIpKBWAVE4P6KHnvBYqtT8GG4yYF8/f96GZEMxgwH/
         FR8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zRwQfBbHOBG1qGi3QjMAkDnw5Ypy6Ma3STWC2cX4ISY=;
        b=QJwXqtqvVjFg/jGCxaH1QDxEcBqIRmczHx3F+Q61msMSSNDJE9ZttwGTxADFcA3shJ
         df17xoOVu4bWoa2j6fHoPOXN5YLAjmly5baGYrzIqlKITLo51zgRClEuYIO6TqDKTuYj
         KW3CFSd1PS+2HPelt5ijressOn4MFyCt2R5mS+q92KHa4jd36NdM/XBDvpUJ05UQdm8i
         GOZqL0Fft66qWkYcMgLFxdJ/RNPq6v6N9118Dp554qmQN/mnqzmsrPABPtKTkorVEd0v
         3T/+E7Ja8+bYyGFs3ZlRSDN2zuiNRQVMNr29fdK1B/StbF18AWS+WAb3xcqEyTie+U91
         xuWQ==
X-Gm-Message-State: AOAM532+8axer27aXJ8/8WfcM/IIhjyIHD/MciO2Adm3FidhwSzzRjB4
	y8cG58Lgj4U4M2rx5L9oZFU=
X-Google-Smtp-Source: ABdhPJw2/vE3ANx3xr9njziJ3G9G3gZo0vNnSap7S1UcEmuYMrCArcOEiP2W4x8McLLYdjmD80wVsA==
X-Received: by 2002:a17:902:7684:b029:de:2133:baf6 with SMTP id m4-20020a1709027684b02900de2133baf6mr5864144pll.82.1611079944062;
        Tue, 19 Jan 2021 10:12:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d149:: with SMTP id c9ls7970408pgj.1.gmail; Tue, 19 Jan
 2021 10:12:23 -0800 (PST)
X-Received: by 2002:a63:616:: with SMTP id 22mr5607604pgg.410.1611079943345;
        Tue, 19 Jan 2021 10:12:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611079943; cv=none;
        d=google.com; s=arc-20160816;
        b=mjlS+SDTdDaWkkmeEKRAkopmgjgxjlXm6oWfoj4VcaCpmML4wp9dLEI+tYI9YfsJXh
         dptQVRRuk/rhygDfczU5AnK0jt+aR91mrjeYVYV62Ox3Pe1mChjAqzQwn59hkwDvjKqc
         mi5mWECMEc0jg/Z/R35HhPiBl0tx3u4GdgrHZOT4v0fph7gM1m7pzstuzWBOK+fqa8Lp
         RpWH+ckwv/bT+Q6M5YuQluZW3ZuWSmaJVn1adOmHgxubUu0hixyFhSOCePhFvl/HyZPt
         hpU5ncjiIgzjfPyivkEFcf1AWsZgfJnjQ/TgbLVJPDfuMLVjyDyaniBwCHOHg9Yb0kyP
         0c6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JGbRgtl+Xd7NnNyvzbFz33TQ6zZwYmuEBrx6vdWmM7w=;
        b=u/pbqynT9aM/bostnRZzczLblu8Ia4RTu5rcVvCuxgRtDZuIUDq86ew9LCNMd4Eos2
         d/OlSyPVyAhWh4suvZrGjhKfxgJdn7hLBhBKfJh/SBtXBuhTL09OlWDNkvbMNcqxtIre
         POfhn6tJhL7Ga3AIp9NTwrYDeCIeP8uxhG7OMcKwaHgYeycF0qM1c3Ensc+uiX9M1V2x
         +IOGv8QK2lFrK5NjtTMmztq67aTabjFFv9qn5E+ZMflqG/BQU69luwwJoHT8VEkV6rGD
         D8PBnwiXEzVkCAiWA5dLSnhopReZ9LZIzNSqVS7ytU4bXj5406pHLsWH/iKj+b/HIFsU
         uo1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uTCh6cTU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id z2si413197pjq.0.2021.01.19.10.12.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 10:12:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id r4so10957468pls.11
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 10:12:23 -0800 (PST)
X-Received: by 2002:a17:903:31d1:b029:de:8361:739b with SMTP id
 v17-20020a17090331d1b02900de8361739bmr6013728ple.85.1611079942969; Tue, 19
 Jan 2021 10:12:22 -0800 (PST)
MIME-Version: 1.0
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-4-vincenzo.frascino@arm.com> <20210119130440.GC17369@gaia>
 <813f907f-0de8-6b96-c67a-af9aecf31a70@arm.com> <20210119144625.GB2338@C02TD0UTHF1T.local>
In-Reply-To: <20210119144625.GB2338@C02TD0UTHF1T.local>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 19:12:11 +0100
Message-ID: <CAAeHK+wcWk_URtGROUc1VLR4PjVQChCUpSLFya9DNTytQP2mVg@mail.gmail.com>
Subject: Re: [PATCH v4 3/5] kasan: Add report for async mode
To: Mark Rutland <mark.rutland@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uTCh6cTU;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::631
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

On Tue, Jan 19, 2021 at 3:46 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> Given there's no information available, I think it's simpler and
> preferable to handle the logging separately, as is done for
> kasan_report_invalid_free(). For example, we could do something roughly
> like:
>
> void kasan_report_async(void)
> {
>         unsigned long flags;
>
>         start_report(&flags);
>         pr_err("BUG: KASAN: Tag mismatch detected asynchronously\n");

"BUG: KASAN: invalid-access"

It also might make sense to pass the ip, even though it's not exactly
related to the access:

pr_err("BUG: KASAN: invalid-access in %pS\n", (void *)ip);

Up to you.

>         pr_err("KASAN: no fault information available\n");

pr_err("Asynchronous mode enabled: no access details available\n");

>         dump_stack();
>         end_report(&flags);
> }

This approach with a dedicated function is better. Thanks, Mark!

Please put it next to kasan_report_invalid_free().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwcWk_URtGROUc1VLR4PjVQChCUpSLFya9DNTytQP2mVg%40mail.gmail.com.
