Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDFOW36QKGQELRBJAFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 238082B0EDB
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 21:11:57 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id 36sf621458uaw.18
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 12:11:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605211916; cv=pass;
        d=google.com; s=arc-20160816;
        b=J6qSUX/ruoZf9HIWc3xCjsflNcwzW/RB/fjUfeD2RoUvi3loa+DrKuTMmMAlOt+qf9
         Jbr1tzEw78puB/svS/h+MaYHzGui2jJGFhwS/OXVomIdI3QNX09dTP6FFyCYMayhYtjX
         9oMSfKtdZUCWdKte37q14arv/jDowlHs5DoAwq+3LP1EZ21uKHPqA3D7m80X3uWHWM/j
         HVZ5GrI88oVky5Cwhu3jKA3cTCrb5lBSqlIHSBbooP5HgMajCftvUoKekMEOECRwf+W8
         M9BBWqxAdwKahHZrtPkGecDD4eEPlOZ2plILTcjhSFk+x82lmWU6znzyPURGjrpp48da
         nn/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=UUZM+XuNFJGJSRrLnTwhXzrXQRIQvYGdfrUiMPjDhPU=;
        b=FeWNEu2Zq0Lg7gspPOkGbFdqWGAqjijNA/H0cTrUaud32KGDkIaBE3m3EZg3OlQR5n
         134wb2/xov0sHn2J/TeI/HrzRSGK0r8ng5lfG8deOO9QmdvMw3VK3KqCOXIOIJnAMX+B
         YovmAReYAhRn4xIjbH6OTtuFJ3s//A4DdmdeAB+HnxKy7xiDDLkQtFNURSdusdmMHabK
         io/a1bJWy/ZOEBVudZSDrz6XLIuf9SnCfAvgChwL0yCgDd3DPGJQ65pYxXSL3HESeu7+
         WT8SWipUCmGf6yTWtKXGpGRwvKCQhZ27KULJU1aO8w8ispxeC64l079jvfwhwBNntbDA
         867A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RNW8PZ9+;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UUZM+XuNFJGJSRrLnTwhXzrXQRIQvYGdfrUiMPjDhPU=;
        b=L2qeVUN9inN1QBGePG2q9d7vkaVGuDQWS1kDD0dIIVOmcD6zZxlTziSZNFpp4Zmh5u
         xczlLukMWfsOK/PYgYPUAckkxzxlRk7xk3dPSV/P+pi+lH0rupTAIy3M0kxcY9nyQSYY
         8DV0jEzkFAfkzBdR/xuyV0NqZn7JCy4a5pcHMcoJCtl3GxKHuM8lrkE6HX4mxIaH6iyh
         5YU5Bnkz3NnTrDb+PGfDBfdfk6WTdMuEYIgEXQOC49prSDoG1hu3LOWM3l9TAe12ROmO
         6l+jGdfV6CuDrWu62j7UQZspJCIXDOFqZQYibHdNNILysfav2WM9fSt4TTwNpnLE21Q+
         vJ/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UUZM+XuNFJGJSRrLnTwhXzrXQRIQvYGdfrUiMPjDhPU=;
        b=YCCpUPqx4L7bBdUZAS9c3jHTd+ioIUuJ0orQd/ayWuhez65q3dKN0rFVmrB3vbwJBX
         ReLtBT2s78AAuajfR2Dzd3iiLH0K8DJwOkPrqCbKGB++f4vF7LwNFNfQ3N7e1UJbX56G
         6VtYGB8DzoRfksa6MXI62FWWBb+tsONfqpNZnGSo7C9vmGMQW9jjY/gJvzlr8ehayYuy
         60uOWVwbnBGG5IGejpKTbhZWXnwJvSjTLZ+9iLH/4qip95XzrYNRHPCOOlLwqjQwZU6Y
         p3sa7JDyZO3PIozSTI84YYj+UEUVTqk1zEv5lpidXHLiPBW/sV2Pif2jgqWEAi4qf/6a
         c4Tw==
X-Gm-Message-State: AOAM531Ghtzop85xysAsejdZChwFzfZH/6XS2LsRvnpflroQK3baNRx1
	MS5cSZGaIb5Z8usRyB3I5f8=
X-Google-Smtp-Source: ABdhPJzZepFC1eWCtcy4V6zfuMCSFiN2fDFTlZHTRCvFQiANBEjhxwV3a+q68ZaHqU9lawBFFvK8Pw==
X-Received: by 2002:a67:b40d:: with SMTP id x13mr1100983vsl.46.1605211916239;
        Thu, 12 Nov 2020 12:11:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5adb:: with SMTP id x27ls314728uae.1.gmail; Thu, 12 Nov
 2020 12:11:55 -0800 (PST)
X-Received: by 2002:ab0:6994:: with SMTP id t20mr1070559uaq.111.1605211915756;
        Thu, 12 Nov 2020 12:11:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605211915; cv=none;
        d=google.com; s=arc-20160816;
        b=fIXy2I/mccXGQW3YXppKWwsjwtdyvOguC9TCA6aPNTv50zSV1DmEBs11zXQVzcfiGL
         cR35p/rXk38PVcfzv0S+HCP68yhYJ1dTwRJiG/4xIkLataZUvxoY8dsTyePXBUAA6eZE
         TjexsOQvEZl3EUeopFBCkhkEphwggotsLDwQCRzHLjctnTOQbufA54hZVjYyRLS0v2CT
         +SRtfsTaTMW2MZ9xrBrVtgskY+ql8TaL3xWVFRDOMh/TdiKz94UJ5zv/XNf1DGlXTrYi
         0hbZIluCrtiJ8nZcbu2FGRS8zFR0oQAYrnp+k+X9mwLo7XmqZRqns1NdUYc3E8/IO1/Z
         6/+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2S2n4Y93UoJG9nL/klprM8z9XQcvbrv6CcFxLYZgtjg=;
        b=ieOYW04MHkD0KwOvtd5ZGf2iJxZK74uoFZDeVd0V3t9J/bwIcBIrMeiqCfuEtIluat
         VdCo7z0bNYdteqpB5r2e7s7r5sDCJzFDDoqqwlBAkGSKhTNLE4kxGc3dVI2x+/Twn2uf
         mqpMdAxxIhDYHjehY133na6EvH44XJi7i9d1XUb8Imcdx+Fvx7fJNZE18gfAYUj/yORz
         UHMkttfdOCgPep9bQWbJhMesJJdXtYjZwE9aPwDyOigJAB7NOZUrYGVgFpsPtwPFaKfO
         CXOCzJIrOmYZpakPw/eqKtQH/bGyBBgY5Ok96sGYfn32yeGFPw0VMDzFjxDPYsBT8LIX
         DU2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RNW8PZ9+;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id k3si621307vkg.3.2020.11.12.12.11.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 12:11:55 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id j5so3365009plk.7
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 12:11:55 -0800 (PST)
X-Received: by 2002:a17:902:d90d:b029:d6:ecf9:c1dd with SMTP id
 c13-20020a170902d90db02900d6ecf9c1ddmr902814plz.13.1605211915059; Thu, 12 Nov
 2020 12:11:55 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <fe30e8ab5535e14f86fbe7876e134a76374403bf.1605046662.git.andreyknvl@google.com>
 <20201111230601.GA984367@elver.google.com>
In-Reply-To: <20201111230601.GA984367@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 21:11:43 +0100
Message-ID: <CAAeHK+wwC7zETg_0VQab-mMhssNwC0_aoh3HqRVqN9SrZTMSKA@mail.gmail.com>
Subject: Re: [PATCH v2 18/20] kasan: clean up metadata allocation and usage
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RNW8PZ9+;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::641
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

On Thu, Nov 12, 2020 at 12:06 AM Marco Elver <elver@google.com> wrote:
>
> > +     /* Limit it with KMALLOC_MAX_SIZE (relevant for SLAB only). */
> > +     if (optimal_size > KMALLOC_MAX_SIZE)
> > +             optimal_size = KMALLOC_MAX_SIZE;
> > +     /* Use optimal size if the size with added metas is not large enough. */
>
> Uses the optimal size if it's not "too large" rather than "not large
> enough", right?

Not really. If the redzone composed from metas is begger than optimal
redzone - we're good. If it's not large enough to reach optimal
redzone - we need to make it bigger.

> As it is worded now makes me think this is a fallback,
> whereas ideally it's the common case, right?

It's hard to say which case is more common, as optimal redzone size
varies and depends on the object size.

[...]

Will fix the rest of the comments, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwwC7zETg_0VQab-mMhssNwC0_aoh3HqRVqN9SrZTMSKA%40mail.gmail.com.
