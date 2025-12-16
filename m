Return-Path: <kasan-dev+bncBDBK55H2UQKRBS5QQXFAMGQEZK4SAAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4254FCC3077
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 14:02:05 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-430f79b8d4dsf1421495f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 05:02:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765890124; cv=pass;
        d=google.com; s=arc-20240605;
        b=foEYurLrWf6X98PRRKCy6BamGLrjrmvB/GCNZXIpwABczigRoF+t+oYuu7cFXJbDEj
         9Eg8GMSvrSGyrpqxgm9RY6So+g9JfyFaU4XoOvs6PpUJiAtmW+10RjnphzCg/7P+L/WF
         S7zOek+WIwgFYN7UTwn2jHXYpk3e6xPBRKJCRN5e8pKtCU904378n+lcQP+pvznCnsTN
         QB+DNp8iTLE0hPVlzjfK1AjTonpBACS/Ghg5Z/sokIBqMcAsWfovlSNWt+qhKm9wh5dz
         zOfA5Rd+cITTm00q2plieM4H91l4jy6E0nsxL8CZvX1F+zDIK5fWrcrJpVHcK02ubdVh
         CaWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QEyhNyJ5DGl0yeHIL2VoC3ZaqZxUyezc1nGlRxwo92k=;
        fh=w2q8ZttFdFSsXIMkMtdOwyqBr2daj1iOHt3kOkF7Xzw=;
        b=eHup4uWg3jCaTK1bjXdLO+eLMnTTdJ5G26RZCZhftIgpg6yX8quy2Ac2K2LqI969rG
         1xg4yAtEswsasfTfavYLj3owChJ7nbwbmguV6WhzyoY3JipbnhQocSmoCtXb+PW2Pwbb
         m3g/RFHS1oc/IG5cjS1D7JNRiJ7WhgkVFVYxUIb15PSYJSC2BBu8xu7oVCbneQszyGu9
         UUtacE2dHVWxM3DvqFbw0xnd6W7LAcGpm2J0/LV9YBanPzh+6nI5AUGUGOXBAbAAUvqm
         v6bXbyuldnuPoqA5Uiexk36Rmraz0bBvV7AISfN+YRVtYP84U1oXFHZI2Z/jpV5qschL
         mZqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=S0RX8SpS;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765890124; x=1766494924; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QEyhNyJ5DGl0yeHIL2VoC3ZaqZxUyezc1nGlRxwo92k=;
        b=SnkHjV2yF/VY7vsbhrM0O8JN8pZoU4L+CzALAoThSlHSGhYIGfoejFajETgUrFyl5+
         Iki0yVRF+y1VLPpjNYA3NtkjPbe7E3RjyjtW4vfebjt9xpL/T7+iC7/e6cztg37OoeHc
         WjtcqcwtWcgOnKC/SkPyG3vXf98wCrViBA4fxg9NJOZxu9rivDrxgY1U4izyXwXJWZea
         WqG3s3Xk5qANVUgprCfPFUhA6IFIVWotFOh9Xj0SPZniH5TOO5yrYfuh++Ln1otCjHD+
         MQ+o/0Y6JuAigfzIc+4seZbTylvnDn6FK/F5AVFoIItfad7Rjqr3WTlU0ofUbv1X/o4k
         pTTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765890124; x=1766494924;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QEyhNyJ5DGl0yeHIL2VoC3ZaqZxUyezc1nGlRxwo92k=;
        b=qU14n7CA194vCT0dWfhbjM44zz8jocGkGEBvq3Sk4deeRszfaYpgsHXDC1dWtiO4JI
         noOunIOAjWnCQpl/nJ+r4I/s63jS1Kg8z7iNqnVvkfQGXQjnHy0U7ldov5ce9eOxRuru
         fMzHEFg3rj31TKafoisSEmpR+brGDovr7tvrMOjD8SMntrfW/EPp40f9H5kD4Dvp9QHs
         rMwDGF1sgbN75oB1lLZuhWZ6jWiECzjBmj5IN4RYvK2qp/AuJSZCfpQyWLQpwWl3nL/c
         E2OkJz0hAINxz0cnNchPHdYcWxq8KnIBWug8JCrXzeOMGl51847KPRGj913w3w/RXcQK
         wOwA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVYUa2wEFa/HcGIPViu10qpy+nQmTGcjWiIVamWo5XUOwXKbqPxAtaIU29DAKSoEWhWCEfPMw==@lfdr.de
X-Gm-Message-State: AOJu0YzLs88TUxKEbhSR6accdpeaKaA5mRUTgUYfJd4/t+s7aXyg/dKk
	dzsytMglMRzT6zFeobzJvegE6uOebZLMOJOY5Z2r3v942bQnYp4+qHhS
X-Google-Smtp-Source: AGHT+IHwzsUyZvrvFeGt7V6E/rJPHzZ726YPBJCnns+RZjo1xr1pZzvTMPB2J6KtBXFv4xFkxoOQaw==
X-Received: by 2002:a5d:5f92:0:b0:430:f6c0:6c5a with SMTP id ffacd0b85a97d-430f6c06ce4mr9621961f8f.22.1765890124476;
        Tue, 16 Dec 2025 05:02:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYUi+0zjQFuPqg84Fw24kH/GRcU3GUqmCPEOk3ExBjRWA=="
Received: by 2002:a05:6000:2f81:b0:3b3:9ca4:d6f3 with SMTP id
 ffacd0b85a97d-42fb2c90905ls1929557f8f.2.-pod-prod-09-eu; Tue, 16 Dec 2025
 05:02:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVDaetMXEpgHKKEpPioffdjrlHITFZL17euSxNPbTUnV67tSf4HZFDilp8wNVLcpRLeWl6rNIQ8Egs=@googlegroups.com
X-Received: by 2002:a05:6000:438a:b0:430:fa58:a03d with SMTP id ffacd0b85a97d-430fa58a71cmr9789424f8f.63.1765890121603;
        Tue, 16 Dec 2025 05:02:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765890121; cv=none;
        d=google.com; s=arc-20240605;
        b=KZkmy5ucx0x3oty3NuWaLY+3M/CMK9i45nfNgVDKH0nI/EuAIy2o7yx7UKvoHHniqg
         MyGObxnNnLlBW7w/szSiO3UWTFOdVey42ncCrd6/uzknqLysMXzqJl++1l60eqqQBEXM
         F9uOzuu9eiNiL0Qrhpr4ZjaSNvP/Z/lyt94iT+0e750EizuKbt6cCzsa1eu9trpByRL4
         7MfottdjU98juC7+WHjxxdELY75Hs1wc8xgc7rQ5Uv2Jj4Imf1KvJ/LXU23CiAX0VGVW
         kUIgbO5Lb9tuIo4hkJOYMUoMX0/i/AKzgHLddZZivA8GYszJiGhAQoazpOYBi6ZUUd07
         O4zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QyaIMcuVfmEkqkRegR+RjMZ6wei1xBk2KIGiuOrqh3Y=;
        fh=1MTu2OJ6DiDq1UCUK7zxZOBEwD4rdSVUMhRltTID3Z8=;
        b=S+lXlZYbNk1A5rCaqJdkl/InZjjiDG6MegPayxmoxHWI0MifoYVUknmgyuBm3nPSFd
         IWcdYkov17qDjg7u+oTlOmVsMdxmW4ej/DvaNSzWG5oGpPlscp73YRtUnrdtACEyiA/V
         kZSSJUA8oFFSvYmGgfBqZt2UhY/4MZptREtalhzF2mK1nvG8JMFWcsoRa4Gt0XDRg13l
         JqPhzIfF5dWs5tVI1w2h0sSizBczTWmxsxtk5wjn7qL6bpyUQbs57T2TD6+DmfLOWD0D
         A1TesCDKuAmU9xe9aQc2KNcFdYwulRh+vAnlRSIHCtqh7ps14OMUtWbp4DEEwK8GrIRd
         F5OQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=S0RX8SpS;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42fbae85baasi143849f8f.0.2025.12.16.05.02.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 05:02:01 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vVUge-00000003Ixr-3VMp;
	Tue, 16 Dec 2025 13:01:56 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id C2B33300220; Tue, 16 Dec 2025 14:01:55 +0100 (CET)
Date: Tue, 16 Dec 2025 14:01:55 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>, Ard Biesheuvel <ardb@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev
Subject: Re: [PATCH v3 1/3] kasan: mark !__SANITIZE_ADDRESS__ stubs
 __always_inline
Message-ID: <20251216130155.GD3707891@noisy.programming.kicks-ass.net>
References: <20251216-gcov-inline-noinstr-v3-0-10244d154451@google.com>
 <20251216-gcov-inline-noinstr-v3-1-10244d154451@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251216-gcov-inline-noinstr-v3-1-10244d154451@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=S0RX8SpS;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Tue, Dec 16, 2025 at 10:16:34AM +0000, Brendan Jackman wrote:
> The x86 instrumented bitops in
> include/asm-generic/bitops/instrumented-non-atomic.h are
> KASAN-instrumented via explicit calls to instrument_* functions from
> include/linux/instrumented.h.
> 
> This bitops are used from noinstr code in __sev_es_nmi_complete(). This
> code avoids noinstr violations by disabling __SANITIZE_ADDRESS__ etc for
> the compilation unit.

Yeah, so don't do that? That's why we use raw_atomic_*() in things like
smp_text_poke_int3_handler().

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251216130155.GD3707891%40noisy.programming.kicks-ass.net.
