Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO5AVCGQMGQESTLW6LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id E2ADC46778D
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Dec 2021 13:40:27 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id l4-20020a05600c1d0400b00332f47a0fa3sf1302412wms.8
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 04:40:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638535227; cv=pass;
        d=google.com; s=arc-20160816;
        b=xYU7Iyd53y0aCx77uA7zKLzZ0Nixa+Erca9J6vYrltX733/mpMPNIm61XLJG19WTss
         d3I14krOSqy5z2ZS1lWqUVHFtIvg0r1A+8RjqVBqyPdQmehLYWgoYNgqN2eCRc75Hieq
         bSBr2qEHsJBqEPF3I6EPT+la6C6g7gZBffhg20gbY8ZhSlySVn/+Q5dAKLfC757g9HhR
         nMj3hJxI2ApVVQvDpEoPBWw7JGVVbYqjgmui/SSlY6Pks6TO7mDmMBQRy88kznTptcQH
         y5VPoyijE8yLDF8bG52ExmIUVDjH4Mc6EyQr+e+FJujuot284Kn/NtcLm1urja6qko7e
         +LUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=0LQuFyUpQuyyA+7TiNYWnmQpvU5Dcf6ebWOqXgxt+is=;
        b=OeguTeMDSafSOs6FEO3LmFFE2PvXXFA8PsREveTrNhzca3+SBnDkUL9HGySFVmaEpM
         APERQdcbbawtEJHTeSmGozeAIahphrWwt/gTphyi23tw2Zb6Pc4RFkfAgSHDsqzPyN80
         rWIQF2u17mOi5bbgTV+9+sMFOgaMl+28W3+P5A9aM0ML43FIrHqV42YZs1+c1NivOGtK
         O5OJnuR7qU5LJ1XAE+p/JkrnXc+xmb7EX0+NbZvMUvZxm/vAdek/HIGi/+2M3Bx+lPi1
         SHAUmNRqO1ZznRk6xtvoI+4SKWgCOb5bDdU6sLem4Wjvt/DsT9xtzn9wODy7XG8EhHnn
         96uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=acLlXvt+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0LQuFyUpQuyyA+7TiNYWnmQpvU5Dcf6ebWOqXgxt+is=;
        b=V6y0whaL08w/J5DHzWAd9/uGJahjn/wvPfdZYJOEMvRGEJ9sHjegC/x19WfvuHn3Kz
         DJw2X/aAeahJII7Q5bt8Az98zB44engx51emfYLCL2wwcp1MMoxDxmE6wdarC0ptFL0I
         VRZhbITuCUy4aXN06chkfWBjuFdwOwTd2c9pt7G9Ps7Lm9KA4rypdHzo7mchyOi8WdWR
         9T/cg388NPUyvEQrZhMYmAA7TjKIfz3MFppXohCcrnwoLlRe5vnAHHRGDXrW284u34jz
         ykrzpv57F6hlFB3CswcouJD7/2JoUzY+zRMkun2SL/jr0OyT1iC3h6Kdo5qBN4fL6jiG
         NJnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0LQuFyUpQuyyA+7TiNYWnmQpvU5Dcf6ebWOqXgxt+is=;
        b=q9yKstjpHQcqARBWGdCDakSMdkh5hRP3HK3m/LmwowRWbCO6FFgbI9+ZnNS3N2TqUg
         R8nNAyzSazEb0XXxaFf0GARMIkFLaLiKx87ZdqsWa/Xslreb12DWC0h+6qF0VMjs1kx0
         Ufjm2TVYSKpDufdhxHkmPRPtd+/LMtDCnqtu0tkqfn4Z7cUp7Bk9/u7q1WRuBWCxXYNZ
         lB8lOIsZ6cnkA1tN8mvYNAGao11X/7bBdoUnOu3QBlfwvJuffrpeu9NTwGH6xpbNXAEr
         I/nxC3ASv8Ajx42Ows3UbVfTCpHnIoatb515TS/h9/th3zSBJlJy0xne9JZzm0zIeuhs
         rBpg==
X-Gm-Message-State: AOAM530yIczO6WQbCr4KcFI/VZU+TQ25Opf/oSHTC7zDjXa37VHdE4PP
	91o2dcVHI/QmAyhc+OeHZlY=
X-Google-Smtp-Source: ABdhPJziYyENkpoqI1S4K/8fpCR2xXQPafGPqOVm60eHASihfo5asONZnXx+hAHrBkJzOFdkYfIDAA==
X-Received: by 2002:a05:600c:3b8f:: with SMTP id n15mr14731818wms.180.1638535227673;
        Fri, 03 Dec 2021 04:40:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e16:: with SMTP id z22ls6693475wmc.2.canary-gmail; Fri,
 03 Dec 2021 04:40:26 -0800 (PST)
X-Received: by 2002:a05:600c:1e8b:: with SMTP id be11mr14832626wmb.40.1638535226718;
        Fri, 03 Dec 2021 04:40:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638535226; cv=none;
        d=google.com; s=arc-20160816;
        b=qToKpg15SiAqQpnpmcgYudWP+uc1TBQyE84sTLsx/Dl/2foCJq/sW7IRVY9OLEJ7za
         HnEKtRfg3lpyDu64Ad+P3mYCAj6qP2qpI45adLhRoV2O8aZxo7UwH1uOD8vSwAMsBUOl
         cRDbSBQFYGWg7cEzTPjTKLw/C1ya+b9YLs/P1P1BTimJ55G/igqzJDqxjciRyhg7sBs3
         nG4YAJKZJizw9/J+7Qkraiu22hqmZ5yVYVjVgr+JcOiD1AYIkj4Svtzp82Q/3OinUcXD
         LaiS+a0zwNx9HjwcaRDFzcqlGDAGQqGayTYNG/9gTQRWwTHZuO6bNmJ0VFP7xvGLwbxC
         w7vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=C5r84uA1kNqZTgloKYxBMzot2+jjFOzS+FJH7QjXhpU=;
        b=txyp1/UQOoftC0Igp/Hl/ZB1iTBTk5DXA988aV1fIcl64untYXRWamtlJb3j+vgc7J
         AZ7vqqsSpoVQi75t9TC38/jzyEq5Fvk2mIu5k/T0h2zs0zum0ht55jzkhz/jJ1Gygj7o
         odRH4MKSr7qF6tgJrVoa5WoG1Eeg8e4P5gSa2dL3/hcL5jA9HMXwe3UBNCX+fKlthRVe
         IngCua+Y9iotR1DCkmOnZJquoyydi4u/B4KkLkR9vGdyVz/UN7wQyLFHV69wkVweXMnk
         K/3yXGZGTA0lNkz47EiLpXxTJ0teFor05mMiyCsPR9DG9hKZH0UFFCch3AWOAyNpjMyy
         2XPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=acLlXvt+;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id s138si395392wme.1.2021.12.03.04.40.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Dec 2021 04:40:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id k37-20020a05600c1ca500b00330cb84834fso4779308wms.2
        for <kasan-dev@googlegroups.com>; Fri, 03 Dec 2021 04:40:26 -0800 (PST)
X-Received: by 2002:a05:600c:104b:: with SMTP id 11mr14952957wmx.54.1638535226195;
        Fri, 03 Dec 2021 04:40:26 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:cb5f:d3e:205e:c7c4])
        by smtp.gmail.com with ESMTPSA id r15sm4816930wmh.13.2021.12.03.04.40.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Dec 2021 04:40:25 -0800 (PST)
Date: Fri, 3 Dec 2021 13:40:19 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 29/31] kasan, arm64: allow KASAN_VMALLOC with HW_TAGS
Message-ID: <YaoQM7xWVKISa5Yb@elver.google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
 <8afdf7eb0bae77d2e94210d689d524580cf5ed9a.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8afdf7eb0bae77d2e94210d689d524580cf5ed9a.1638308023.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=acLlXvt+;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Nov 30, 2021 at 11:08PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> vmalloc tagging support for HW_TAGS KASAN is now complete.
> 
> Allow enabling CONFIG_KASAN_VMALLOC.
> 
> Also adjust CONFIG_KASAN_VMALLOC description:
> 
> - Mention HW_TAGS support.
> - Remove unneeded internal details: they have no place in Kconfig
>   description and are already explained in the documentation.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/Kconfig |  3 +--
>  lib/Kconfig.kasan  | 20 ++++++++++----------

Like in the SW_TAGS case, consider moving the lib/Kconfig.kasan change
to the final "kasan, vmalloc: add vmalloc support to HW_TAGS" and only
leave the arm64 in its own patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YaoQM7xWVKISa5Yb%40elver.google.com.
