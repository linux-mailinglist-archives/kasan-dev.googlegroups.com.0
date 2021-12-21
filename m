Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2ERQ6HAMGQEXF32HIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id B8A5E47BFB5
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 13:30:32 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id k11-20020adfc70b000000b001a2333d9406sf4643001wrg.3
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 04:30:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640089832; cv=pass;
        d=google.com; s=arc-20160816;
        b=H5s+JJWSNpe6O6u0EMRVnGV/3+tkJ0vrPDW9GP4xtYEqzBaeHUdei/SQXYvxmFpVkV
         CDJvobfK7lwCW8q8SsM79GQ1f8jNjeBPBsNMqCWLDVItaHa6RnKUAlmw/wBPiejjGhbF
         bQZvqEqxLXYqhiBkKIU53cd/TIbwlOrbXs2fqiRM5tBBipPjBrmJiib/bJBIhSZsM9KR
         kvIYiT2yxnrNXvG8Q2qf99LWxTUOgG9vQ2Q+kYtYFUVBwe4Us4Ys3+BGs0FnPrbvrmjX
         uDwQudMSNZP/p1zZKbbRYFFK3/iO0AIo64ezt+ibCcyR7uMc9sj4WYLW3mYquiIt3wr+
         DOUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ZjM4ZEzxngec79nz8Doxd4nN9/3o02FnItEZ3OEjm3w=;
        b=egWLSkSX0kv3bX+Y0jbjMVaL55Xpm4kL61JbIkOck3IlrWEMsjur2qv+ZDkhh6fMcN
         T98FXtl85Oht87ZKRXNvhf1Zi+Nk6DaqzQcT+aTucB5hb9MMqT79CTjRjbpMBF9fXRa7
         +J+z3cLGz1A3NMp3rfFvNv4jQ7Xxqdww9UNy5KdSWrg0rPMG1qoQd4u/HGZhnS7JWxNT
         bjGIur0ihDF5xi5yb0JShkrde29tnDtUCaSq/YReJt5SbCzgFMsboPTUVGBShS3ZzMdB
         Psy6UduOjA9KHTD4AtZrrBODjAbeW948+uHRiuBblNTnAAERGtvNaF9ghxbcxoPk/F6x
         koTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DIaobCco;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ZjM4ZEzxngec79nz8Doxd4nN9/3o02FnItEZ3OEjm3w=;
        b=P+LwZ3hdbUOrMeYfteCxtairsJ4NcrPRxxa6uhl6hT1xZv183yt60iUjpaxABdpAcA
         JWjqNE+tjMOsqbrzMmoUTPmxvmZnE+QiJA/juagHaABi15HkDh95PTf0O+YdcSjspmpU
         sRH84VeZJ66DGj83UFvw+P9RjB7fz923zQaeOfUWgTL1IV5ZrytU28o464ku6nyx/qme
         ONwW/H3rtdJGb0LIuwE91o6kHdvXEKvqge25LzU3Rc/9UXieqrGkb9vRVmHKFx4Gi0HT
         IbMjRAvlZOQXe23vcM/ALWGrmA3aaGcpowSIr0aFyo1xUpiqEAiX89Uj6mw2sPD0J/UY
         y2cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZjM4ZEzxngec79nz8Doxd4nN9/3o02FnItEZ3OEjm3w=;
        b=xz4Jhj09PuD/crjMHCabL0xX2z1BGGh/SQ7nKa5BX42dj2a/BgsrY8ga52G4r2xKVv
         HG7WoITYftCpEvybjObEiJuIKQpFox5P3CXnmjZX9vP4IGWAXhv6Vr/WxfO/kWEK3Eve
         u00P1B1/eFzndLTIHgPVS3m+Xa20KTwyl8Y4WiNSbBCpEYjm7kKLwEWfMMhid55plu6h
         k1JaVL+Kc5sjA1UEPMvvnOOVo9+C2TszdFAag9aGrfCjGYuCEqTLoxpmTK6ZithyWCNG
         Hh2Y5k3gchDtA8ZquWxGWEAQROYFiZ+K5fiVTd7hTBKzm0CJy5umMq1XMOHQOrZBm3Gl
         vcBQ==
X-Gm-Message-State: AOAM5323SIJTzuU8m4f+zMS5oOwMp4zVSpPRW5bmi8WhSjRQML/aO9dU
	e7AshxnJGLqqIhaz5unsvr0=
X-Google-Smtp-Source: ABdhPJx0KOkiI+rlfq7qVyJZ4Qq/vvBcP6/M2ZpBxD44HKDON0Hqg+N3o/IjPlhfUlr3xzga+ephpg==
X-Received: by 2002:a1c:f304:: with SMTP id q4mr2557537wmq.162.1640089832484;
        Tue, 21 Dec 2021 04:30:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5082:: with SMTP id a2ls9252244wrt.1.gmail; Tue, 21 Dec
 2021 04:30:31 -0800 (PST)
X-Received: by 2002:adf:9bdb:: with SMTP id e27mr2490858wrc.417.1640089831547;
        Tue, 21 Dec 2021 04:30:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640089831; cv=none;
        d=google.com; s=arc-20160816;
        b=m1FQPf6nR9iGmduz4Gj4aBv4jVe2CPPdPAf9nxCuAkEjs8aw7ezcoRolc1B/gCSoKO
         Y6hjK/3ajSLymsXZin6zxIyy71DdxI186gvOLDllpGqaBY0gDKTZkA3B2/Tb5DQAIYX4
         z7GNRNNfYL0Uzp2dLU+10gSKYA0FGjg0NYNtW4OrCGDPi+zeTyx1SzaEY5lTrskwDQiM
         uVW7AgRJNGsoTgb04fuJ8C4QJpjRPy2FVTamyVJi+0I9xLTOy+0WU1ljbvXE7k9W0YpI
         RQcXnivPnu8gzbcBZfkiXFMAPXHhZr7JTKf+ykediBcDF1+0R5q5oPjxyYHptXvaw3qk
         eFXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=FnZQfonqJQZhort/TdYz7jT5v9CBQGfdqTN7b6WIV6M=;
        b=BimnMIj0I5vfcl0VdXUjo/WTtxXkAUSnDnaQz91D3Kq0y/uLiorO/jZRwmfhkUl9aS
         tOU+nLz/2Kw+sBzUyQSa8bg5S7DO0uTe/SHcFv8f+Fm+pMp2e3H5OoKF9B9nNPK1dRy4
         gtebeYlLzJVEMkjaIrFrNcy7DkWPkKivkrfk80xTlqVa75WG3fWuONzrgEXB5Cp2Ez1T
         vgQfHySKN+TWA2JIrcCDHu5qRAvTkvZW/D6qFcPxAJ8/ENqU2LuvfIaXCr6exhhxEvIc
         HQjKGBfMxNqcKHW4LtRZ7arYSd6MyJp3mZ0VUNZxO4ObETaETXJYRXUMfBLgZkBSNxtd
         ybgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DIaobCco;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id e5si420562wrs.6.2021.12.21.04.30.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 04:30:31 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id z4-20020a1c7e04000000b0032fb900951eso1572491wmc.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 04:30:31 -0800 (PST)
X-Received: by 2002:a05:600c:24e:: with SMTP id 14mr2494370wmj.67.1640089831086;
        Tue, 21 Dec 2021 04:30:31 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:87ff:799:2072:8808])
        by smtp.gmail.com with ESMTPSA id 14sm584579wry.23.2021.12.21.04.30.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Dec 2021 04:30:30 -0800 (PST)
Date: Tue, 21 Dec 2021 13:30:23 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH mm v4 29/39] kasan, page_alloc: allow skipping memory
 init for HW_TAGS
Message-ID: <YcHI34KT8Am4n45x@elver.google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
 <dea9eb126793544650ff433612016016070ceb52.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <dea9eb126793544650ff433612016016070ceb52.1640036051.git.andreyknvl@google.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DIaobCco;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32a as
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

On Mon, Dec 20, 2021 at 11:02PM +0100, andrey.konovalov@linux.dev wrote:
[...]
>  /* Room for N __GFP_FOO bits */
>  #define __GFP_BITS_SHIFT (24 +					\
> +			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
>  			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
>  			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
>  			  IS_ENABLED(CONFIG_LOCKDEP))

Does '3 * IS_ENABLED(CONFIG_KASAN_HW_TAGS)' work?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YcHI34KT8Am4n45x%40elver.google.com.
