Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPXYYWZQMGQEPSVEG5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 86E8090CB94
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 14:23:28 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-2598b09a748sf268760fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 05:23:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718713407; cv=pass;
        d=google.com; s=arc-20160816;
        b=ErXn3CI5PNvOajzJ+QQ4ci02oDl+AP0lDKHYQwZuQEfzLDUjVyDqm2nug2LT9+5vev
         fQe41A55P/ZyZs4l/zbtAgIuEqk+sTxTpvX2iGy1BfPV1p9O04JCP0vGzFFKIOBg6Lx7
         dOq2SODi7vn6iMr+2F0unki4pSe4sYtmfDEcJUkmPFrr0bP3XAbr/q/6NxPKlNZEZpzU
         eec5hu3PJK5jXr87zpsAoKJG+w3OXnyqHfDPRjg/ASJgaN5g4MVrDSlb6el1rfiSYdwB
         pqYKePypWahPCY1AIcjvfIgBdqRjhMeoDLwaPSiZ06JapV7mqKmhcBkS1ysah4DEBiBA
         nQzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9G30LKYVVHLbHT5VmefMVv2FzBGhhn6ow9NPGbkEuQs=;
        fh=TQGhii911xsuvDYa1WCNQ/Kpx0IHGzgwbWTPZfjaVfs=;
        b=W0irg2SgHz65w4GMa8h8dw09D2w+hCd7Bh392k1RsckDo0eCJ43lqNGERipSyNXMI6
         8I9pWmkyrNWMw6/5ztzaOJLfg9zw3qmv8tVhA3nXpzbAy7cioMa7FRUiqrHbPLvyX0sK
         EB0T+Ccrhu227RS1twoeCjuhxOMO5j4OLoshQt3l1my6CeJuj4BLiafMH8iuk+BFGsc9
         QYGsIENE8N6NGst72LLgEFquZZcfVjWdlT2MR01wGhCZKRthByr4ze06XoJXBUDkcUkA
         VYf+FC2ft4mjPNLKPJ/mTjTQcE4EBJl+HT4aAXOCM/fbI8SceTLPNb1l5JXASu+giErA
         5IWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=a7k0t0Cd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718713407; x=1719318207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9G30LKYVVHLbHT5VmefMVv2FzBGhhn6ow9NPGbkEuQs=;
        b=ZRXAoOjb+lLi8XXpkuHtaGaTkSP10mMllXUSEcwIeX+KSvz+CAO53c/h+s3Mu8t5+4
         1wFl4uTEIg4ZDRJi1bXFf9adsUGWjnxgPi5BTigDY3I0dWuhX+nBvZA4ZpkKXRkhLavn
         u4q5obRMnK4MM3sCZxDs3EdCI3e9fVKjV57kbMtqDiZpHdywXvZoSySeSVUpahrzkz11
         8QN7LwidavXhyV3eHy+nk2PuePmdVEX4Kz2SJZKNJULrfVMbOZkP89zThza1cky0fOaZ
         23iJXckkAIqW33kIkKIpAOM3WgTDt6kGqjzA6gTtGUKpkOoEkWFO+ds9aZXqmd6j25n5
         ZN8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718713407; x=1719318207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9G30LKYVVHLbHT5VmefMVv2FzBGhhn6ow9NPGbkEuQs=;
        b=hJnqNF5vFPYyb5kuNcOSTj33Djwsi8t5g0RL7rKnsiGY7XKvVc92AihUEL/hCYR1TF
         mCTjhDfmFsu6x/GHybC4tivifb/FwSDrTmkMtqjiLRJACpFihvDtrKERN/WFyDeweRP7
         IpEB/YGuShBNSQA+c9v3i6az9tyk2nnYm8qsRHnh+UG9h0v02nda2anrWoELTyi+v5qR
         x8lVU6YsbVwPIW9nazBC0UKZ5+M8OdUrIu5gIqGI9z13EjnI2HlN3OLzjfiqKn6iHmUF
         6HPk+iEyp/SMPA9O8uTdB5DXAf8Xaqvr5SvHhFtliM6B8Sh0zzZ/cNczZyhGCLFRo7C/
         WC5g==
X-Forwarded-Encrypted: i=2; AJvYcCXDmPvt/GuTz25Q6N6QkKrNjbLW/RFKD6vZ/lCivki+HFzzQhw5Hsbm+4gCX6w08+g/6uUUFXPaoqC2JiITH50uFF/rFUPvZA==
X-Gm-Message-State: AOJu0YyFAU+f2W2i5G8rJ2e8E7qSveP8spKRBFVQzvwMETje8fanJ+fZ
	RAVQKEqYUH04P0S2mRc5EdvGZtwoj0LjJsdt1sXdo1k7TwnFQlYP
X-Google-Smtp-Source: AGHT+IEevlsppbpf9zWYlqEu7v4knicXE9VK9cKwHuNspbPQMTaawgFTwgFZ2m+tviXRoZ1Vt3s3nQ==
X-Received: by 2002:a05:6870:b61f:b0:254:a613:1907 with SMTP id 586e51a60fabf-25842b80cfemr12656765fac.56.1718713406987;
        Tue, 18 Jun 2024 05:23:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:75c4:b0:250:a95c:3b4d with SMTP id
 586e51a60fabf-2552bbec9f2ls7279579fac.1.-pod-prod-03-us; Tue, 18 Jun 2024
 05:23:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmQ8L4A0cPwZgJolNLpf/tjIlyOw6a4ecxbq/6ReyVzoGRovj1miRDq88mPnfUZdHtNYcoFOWC+8GxsQ9qduD2T685trGQb/xSGA==
X-Received: by 2002:a05:6871:713:b0:24f:d12a:5f1c with SMTP id 586e51a60fabf-25842b7fe55mr13114173fac.53.1718713406176;
        Tue, 18 Jun 2024 05:23:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718713406; cv=none;
        d=google.com; s=arc-20160816;
        b=YX8evMWMcD5j14KtBfARi5yBmSWifGQ7tWmwuw647vu5zAV89p+TbcB9RlKrxGVwz+
         zcg28QxdUFGQe4M8g/s6Pe1InpxNfpEFx1y76HxSZzAn3QRIN0in1P+DHZz/x0S0amr0
         VjEHGFk0lx02xRgYrEc4e/IjhtVvRX9dpVbTKuoOyVGb1BIDNQ8T0CpgrPwp8RWHISdQ
         apAx8czQsmPNBqOdi+jO0Hwe1s8Hy5/lJle9r2tmwFezxWZQmkgu47E/oOCvZzOKS6z6
         p1akO0Rn+QvtqjCzkcE3+Kp6SdmnUWY/NFf62aG/mD4ATy5/eorTeSQP5W+Jwj3rmkt0
         UITg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7r9377QHeRx4YGuRMxxudwYWoomRsoHVd1b1XjrAH4c=;
        fh=4LjdUHPfL3ttqFFzPa83L6v7oyXSCeroURjdBbhr3S4=;
        b=Zp/A/w2SpHuPnCGp8j6wftpDUuUewLqkIHZ9MPumrowxfg3J969WoZK1dEVh+2X6yL
         3V1uPzDOQ+EW5eKXBrzR3Wo8QfKI1HbhEmFAb5JnC3Sz1sQqqJc8FLIAzMYxMuBWM92t
         n0tq2EYWlIRzAUd/mWnQpuLDBhEAmNqQnL61O703pFV/BaIOyEXOmWp7xYAMRzY2xGZu
         ILO9Y+l0hI5MuSclPnAilJiSBTNCswaoclbh72Y8TFUrAfcXOJHK01/l9o25qhd7lKwR
         wWgMmrUKNSj+dralB+/8gkqWwTZUEykMZLIAQ6lqgHnxkbA22M0zkC7WcCyx08DWDGBb
         FRrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=a7k0t0Cd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-25699377358si528914fac.4.2024.06.18.05.23.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 05:23:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-63152a07830so44746137b3.3
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 05:23:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX5dBr/NzwQKzGdrcNIMDySa5YQ6Msf6PfMO6JzouOaPGrkZTqsBfMRDQYSMsHjK5ssyC+Pg+VRWgaihq0WGKXBX3BC9zCWRF/Q5A==
X-Received: by 2002:a05:690c:6a09:b0:62c:f01a:17a3 with SMTP id
 00721157ae682-63222a586e9mr136731667b3.15.1718713405543; Tue, 18 Jun 2024
 05:23:25 -0700 (PDT)
MIME-Version: 1.0
References: <20240613153924.961511-1-iii@linux.ibm.com> <20240613153924.961511-12-iii@linux.ibm.com>
In-Reply-To: <20240613153924.961511-12-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 14:22:44 +0200
Message-ID: <CAG_fn=UEutgfgiE5xcFT=LXk51_PYmcCXCeNg3zSSEPYJ+tttg@mail.gmail.com>
Subject: Re: [PATCH v4 11/35] kmsan: Allow disabling KMSAN checks for the
 current task
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=a7k0t0Cd;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Like for KASAN, it's useful to temporarily disable KMSAN checks around,
> e.g., redzone accesses. Introduce kmsan_disable_current() and
> kmsan_enable_current(), which are similar to their KASAN counterparts.
>
> Make them reentrant in order to handle memory allocations in interrupt
> context. Repurpose the allow_reporting field for this.

I am still a bit reluctant, because these nested counters always end
up being inconsistent.
But your patch series fixes support for SLUB_DEBUG, and I don't have
better ideas how to do this.

Could you please extend "Disabling the instrumentation" in kmsan.rst
so that it explains the new enable/disable API?
I think we should mention that the users need to be careful with it,
keeping the regions short and preferring other ways to disable
instrumentation, where possible.

> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUEutgfgiE5xcFT%3DLXk51_PYmcCXCeNg3zSSEPYJ%2Btttg%40mail.=
gmail.com.
