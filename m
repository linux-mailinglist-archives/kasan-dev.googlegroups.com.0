Return-Path: <kasan-dev+bncBCF5XGNWYQBRBLPZ32NQMGQEK3DXQDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E5C462FB3D
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 18:11:11 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id s5-20020a9d7585000000b0066c7a3ddf59sf2222003otk.13
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 09:11:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668791469; cv=pass;
        d=google.com; s=arc-20160816;
        b=ndeFpdVtlf14zG54pdgm2vRvlsY0QZ74zuI2RigHzviPyilOLyGUSDnZLxmdSFY/QD
         dKP5IOFfZSsO0Ktv3altXIprPDOxFSskOMKXqo2ivrgSWgfsgsbM8sUj4zAvDDylKT3O
         sieEksiB2JcVjeTUIvxJ1fI9gUMeX4fXejcnkFBiQOLlhJpFnFXtOU0eG1EZuguidM7/
         EhFkHvAcHC3p8+UE3tJArRZoXHdkdQThMIIwXQgtNNq4V8vg2GhfapE1bBlfv3B/1qpf
         9Wx/e37h//goaqb5jYxiQT9FXNGtHd53oBotKBpqKm0eU4y/qf0xw+hg+rUYV18br788
         N/UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=I04H5HZ3UC9bEMsj1nSr+iwfnNwyx7O7bYETzwsrzYU=;
        b=g+oAEoQW1yxJg8j6sV4zdnUriMpcLkaV0qxBVNPiVRqicdtv6BGcaCkAUuOSIlr9UR
         ZF9CIuOj0vMv9CKhpe6BA8tKYafKqa7KoxyaprCk6rFFpt7VDFzQbzc7qGae7yFscGX4
         61QBttY1yanjeVHaakSxLwOttOJRI3S7qw5LcA98M9ExoZGNow5HAjfCTTRHaCuTeSkT
         yZoL4hKaC38/eSrSbVgrGOC3gRTiga1+U7rxcGvRDjLaEKkikaIpK/iA+MsJAsKJtcd3
         04F7LSo/v7CPVGma6cc0IErMDliD5IBToyhAGmbxwfmxvAYNnxCqjBImROPErQws4cz1
         YYpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mmBzH89H;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I04H5HZ3UC9bEMsj1nSr+iwfnNwyx7O7bYETzwsrzYU=;
        b=a5Uv0rdtG/JzHWlJzPJ95u1oqRGyiVajBG8EZm1MIPaEQeAHtbu7seHdGgyvDMzwHo
         xPPT5CWxaNRdjFm9I2S3rfWdue8ebmb8h/tTmZitY0VyPjQE3allikczVsBK2qGx8O46
         jhiRHbs+jtl551p4X7SekIq2yN4dTXS0u/w0G8fMeCjcoMg3cJNa/bRTM1IRn3V39leY
         SkbmAF3UTm0YKuxlmM4zTleljJJPjVGru7FHPa7o++JbMLexEiZ485CWXoStTFiuKlde
         y+dT5+I8iJ/oK6wpXAuT/hjypMgSuB8aMWH+bBikJ1w5AswkLITpG/dNGjNQxxvATIS3
         s92Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I04H5HZ3UC9bEMsj1nSr+iwfnNwyx7O7bYETzwsrzYU=;
        b=s0CAnjBy4Tz8RLN7DhiFVTTFqYULxL7h2+ub/6w+auHIdwJP255zGQ+8r6ppYnMHNX
         nI9iNPpjK75OHmVm7uFLO9eVmBt6teF0HUaltPkmFaeIrIeFXbMwDXE6ogK/oVtWhmdH
         h57OgP+z7IOYchy5lEPl3MOE6dDTZAoIRvOJo+WivI4FAser92zTGYGQ/fzJVs/RM0OC
         BKbIetJV4EgrYCLr35/hqaQ4PtUS472e7yZKKhKrSj+q6nA6qzDHohlqUQlMriE9vH3R
         W73wnm8UICJrOSkY9exSc0pa52ghjPO/QB0rS6DaBim3F8KtrEG33wZc09xQCMIPyZg5
         eeiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnB4r1zXXQPMD2crdvwxCx7GlmYTcD/GHl3SJooLPncAIGyctJ1
	EBhWU6nOBQmxiQyKKZgVwcE=
X-Google-Smtp-Source: AA0mqf5aJ0xANCzJxf8HwOP3V9StawVwNsGKBTAtdL2AnR0y0Sc4al2GYXAfgFhSZsvlzego0dDjKA==
X-Received: by 2002:a9d:5e0f:0:b0:662:2458:3ef7 with SMTP id d15-20020a9d5e0f000000b0066224583ef7mr4345312oti.150.1668791469661;
        Fri, 18 Nov 2022 09:11:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4313:b0:132:a931:6a46 with SMTP id
 w19-20020a056870431300b00132a9316a46ls2005607oah.9.-pod-prod-gmail; Fri, 18
 Nov 2022 09:11:09 -0800 (PST)
X-Received: by 2002:a05:6870:c99b:b0:133:8a:3f75 with SMTP id hi27-20020a056870c99b00b00133008a3f75mr7454207oab.264.1668791469182;
        Fri, 18 Nov 2022 09:11:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668791469; cv=none;
        d=google.com; s=arc-20160816;
        b=mxpaznC43rbuAOE1bQ+YWy2MBXuGFo9Ajy2qOkad5n1oFKjLqAVeLFN27aEkSich/f
         ElAF0nYlA+phOHv9EMnbYbIKMh+DnS7WLUYwLd6j5PTOiQicExBuWBXzqvXW2sRf2Kij
         PT00wl7pzO2cfR+oblx1SsYh2pkvagtv+CDtCM/uYk9Ntti8sSuRoVLqwaOZRI4hLbou
         M2JGy2fSbJF56BBuA76bgGYbsnfS8xBX+j7jRUp55rw3SipeaOBAdX6uOnr82v45BY4e
         cWL/fW9ODJi7zGfn4XeRfMBuYwOASUZ1V7AHzIYezeyI2ThKq/iwngXk01m/EKIAERvC
         JTfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cDyeQiupLB9oqNpxPK4jyqPn5HRNeTYV3/chespM10E=;
        b=pGFYg8UkzuTKYJZl/7KyHCZ/idqimjrzucCOkXayl5RiXXeG+Bgmoaan5XWpnPNYtx
         Vo8zIBDYDfTYBJ7mk9bvQ672EygtNoAIz0zforasrGYpy3sbZkdf3RpVi1O2tW8fCvGv
         7h+gMR/o5upAbsEuCHrPa8wHw65UzXm9B0NpCSuBu+vNhCH512SqXlW4Hhvu56Fybs0F
         zoj3iSLxuunOnFQ2qndfYDyc7eHzHwbrH60XXpINdpc0YyEFsKy8ob0Q2B95qD/vqDAS
         u0ASdCfxi9qbsj5Wshbdv2bytDwYQa/NBWtS0pmDM757lI9jTlXChfaiSxR2pSe8YXYK
         Kyfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mmBzH89H;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id b9-20020acab209000000b00359a21e3ffesi269759oif.2.2022.11.18.09.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Nov 2022 09:11:09 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id c203so5436835pfc.11
        for <kasan-dev@googlegroups.com>; Fri, 18 Nov 2022 09:11:09 -0800 (PST)
X-Received: by 2002:a63:ec11:0:b0:470:5b0d:b50e with SMTP id j17-20020a63ec11000000b004705b0db50emr7217183pgh.488.1668791468487;
        Fri, 18 Nov 2022 09:11:08 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id x6-20020a170902a38600b00186881688f2sm3884671pla.220.2022.11.18.09.11.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Nov 2022 09:11:08 -0800 (PST)
Date: Fri, 18 Nov 2022 09:11:07 -0800
From: Kees Cook <keescook@chromium.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2] mm: Make ksize() a reporting-only function
Message-ID: <202211180907.A4C218F@keescook>
References: <20221118035656.gonna.698-kees@kernel.org>
 <230127af-6c71-e51e-41a4-aa9547c2c847@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <230127af-6c71-e51e-41a4-aa9547c2c847@suse.cz>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=mmBzH89H;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Fri, Nov 18, 2022 at 11:32:36AM +0100, Vlastimil Babka wrote:
> On 11/18/22 04:56, Kees Cook wrote:
> > With all "silently resizing" callers of ksize() refactored, remove the
> 
> At cursory look seems it's true now in -next (but not mainline?) can you
> confirm?

Almost, yes. I realized there is 1 case in the BPF verifier that
remains. (I thought it was picked up, but only a prereq patch was.) I'm
going to resend that one today, but I would expect it to be picked
up soon. (But, yes, definitely not for mainline.)

> That would probably be safe enough to have slab.git expose this to -next now
> and time a PR appropriately in the next merge window?

Possibly. I suspect syzkaller might trip KASAN on any larger BPF tests
until I get the last one landed. And if you don't want to do the timing
of the PR, I can carry this patch in my hardening tree, since I already
have to do a two-part early/late-merge-window PR there.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202211180907.A4C218F%40keescook.
