Return-Path: <kasan-dev+bncBDW2JDUY5AORB3E3XWPQMGQENAEVZ2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 78E4B69A898
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 10:50:38 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id x10-20020a17090a8a8a00b00234c1d817a3sf1225303pjn.0
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 01:50:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676627437; cv=pass;
        d=google.com; s=arc-20160816;
        b=otXQZpEgUl6Q5ONsWsuzERyJRpYCycsGMtuQzFkbBhV/inu2KwneRpegfRzXanq6Ry
         JMOXqSD0y8ykQ1xvkO8lamhAGF6o/TsWFT7k2tuJZAw+aK9AUftGQt/y54SnH9lCEfLn
         RYPe0pVHfivhgHGl0rBbnzq6A4v6+oKXLjY6QjR+N2pOuC433yTG7mKqRTk3XFQOLg3T
         /ggyUnI4ckK1lpqwCjh5dvNpHc9MWpfky97oIuBV4kaMbiYTPjYBCB4dPDYby3I32Bbk
         oAsh6naHmPbk6BcZLfbaxNW1x+zmF9n6sbbq/ia7wWuCr4nuz5LbNPYDDm2LdUiTmSEs
         AE5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=qBNs+P+qiE2o8EkS00UYImYIk9serX7fX4k/wYF3rWE=;
        b=crW1y3AU/zRT7QbgMvmA3TpdF0MMWEfnQAMUgyMDBCS+5p2vE+ESaes/XrL+/enYt7
         1lC9HozfikNTRP6/n7f24RN+J3uk7SsyOK+R+aNNGIR/54gX0J4XN6qanaoIsxb/T0Te
         QDu0nBPYucdhwAGr7GsCWb25i8hDrbSCmz9qTMiFOGC5K/A2h3tWBBfC4+W1OM794y07
         UE2Z/3u3J690jHq5YC5o3uCst6NdEQipPN9kzNuX2EmitLLMbDgOm+hu7UFHsV+Rm/8G
         r7uTLLldSdPIOuJGzjHKARzebBKTn8bDQRoz1m7qJy8/KWAukX7j0SdoakL1d2Xa2Ytn
         e4QA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ldqJT16L;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qBNs+P+qiE2o8EkS00UYImYIk9serX7fX4k/wYF3rWE=;
        b=DBAvmMyHc6Yx9ggZP7p+TsGSLpavtFzGvT5pSmIKkEPi7GNDo6nxDl91XMchLkSIle
         oC/Vx3tbwFqoB24L93fJ1QhYrnc6CPfWT4ACs2vUOinRhjM56swE7mEUeUO3frdvBav5
         Hlc8+x/7jkSJXQ8AgLjG1rrZiJ8V8L4GhAQoo2OUj4e8Ti5U/t/u+e+vbIjI0wk7qPF6
         MR16nFNktsWwUSZ0BUYQ9ziVv8TYvnva5Ej0PTgH3wcwrfmauBImnPouwbXjaIpN+njT
         jznt2OqZx1w8KRRUfRgzIPFNlUjN14ABKFZ7Uk/oCowx06P0tUG7/dr9XydCBlAMl0Zj
         7ZaA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=qBNs+P+qiE2o8EkS00UYImYIk9serX7fX4k/wYF3rWE=;
        b=Xm8TJiHa/SZHVQlHfc4isHry8njSIHV+a5z8DLW0YeUmT4vLJlxxvxbSAvxFJuQb4j
         Z+9i+pNkd7jmEOKqTxoSSqhtfHQgNwdzmVDZHptgIBjltYtPYxFyO3pPBpXyQb0HQeZu
         +55td2/kYq+XOlfTbrVOQH91blKam4LqMrzgn2DCzpHwtvkOqoFLoWDkr+NdLBiTx6Fj
         KYrcED+XPrdaM08yvM0x/uX0k2zh3/F+kK43qrXJNO0bc9R0nyrmEvq7kdNZ1X050BrM
         5FxSBY3Q0bX2gcSwvStW5qDBURL1nxH8QA1fHtlVSLp4XKLu48+Fb0PStSBO/jIIvPnE
         2Gjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qBNs+P+qiE2o8EkS00UYImYIk9serX7fX4k/wYF3rWE=;
        b=BrWQi9eBHYQunF6vfVMc//ARznSm47KY/YdVBi9x03Q8/hHRYcTNHd3Bd3ne2yNMzs
         33ZsYdTATHPAOisvggGWNwYS5LH/xMM+j2OcAa9vfpaTJJ8H5cIu0SSQoP2JJe4nWn3x
         fzTvAwXfz2pAcmUBkF6t0E/YZhZ+NXLc71ZWnzTOsOxbpfIpTbdWzeShp1EUJKTBi1EG
         NW1oci6cEvT0LGgarJe3vPwbrdm5rMdfBkH9k9+S6L0LoT5oudZrPi3EOFzRqrSjJcLz
         NU7c4zYQJDYI+MGdLOvO1zEx2E2L6q6R2o+tpJkcZfF3+6LOPbzd8jc88i6lABhX08TB
         1uyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVylp3e9e/SzwqjF4NHzjXzPtyzm4cH3xUoF9IVfAHwZz4tTQvj
	ieBGVfIW0k4Spr0K6Orn47Q=
X-Google-Smtp-Source: AK7set9JgtuiD+RnC/p8V0RvyFi66e//x0ag7JQlGetlHehOb59WA5cxVAi60TxzORKNEoNmBsGLug==
X-Received: by 2002:a17:90b:4a86:b0:233:f958:1e39 with SMTP id lp6-20020a17090b4a8600b00233f9581e39mr1348402pjb.40.1676627436901;
        Fri, 17 Feb 2023 01:50:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b618:b0:19b:e48:e479 with SMTP id
 b24-20020a170902b61800b0019b0e48e479ls2891971pls.9.-pod-prod-gmail; Fri, 17
 Feb 2023 01:50:36 -0800 (PST)
X-Received: by 2002:a17:90b:3a82:b0:234:6c1a:8dbe with SMTP id om2-20020a17090b3a8200b002346c1a8dbemr8268840pjb.3.1676627436200;
        Fri, 17 Feb 2023 01:50:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676627436; cv=none;
        d=google.com; s=arc-20160816;
        b=T5q38fS2kEsg4Kc7WNHGMgj/sjMEgF8mx0hKQmyy7isZ3I3VU+qZo55g9Oq+UqkK5V
         pZNufN7XVbkXeluF+iyB0RHK+yYliuC2fh3DNfenLEt2FjyW/a6ovLSmLVAZwCmHGMxF
         R0RXmKb4wDw9XIkPvkn+7eOycXxR6xj5HrnIlyAcz4MWdXr4LhLWCZR4cxJjC+T7ZHKB
         N+AqhW8nBBVPuaKr56U6PO+Dpz4lh8hkdCQnHC2teo+zq3WJoS21i666DQlbARbKwwGM
         AAwdVc9pEVVF643jPK7nGckFLLoaLTx4ApxSO/QKYAbjQqef1oqVB9ZFcp/S3MnbXhKM
         7BFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TTTi9sqA4taT7mQsE24E/BMxLx1RUOLEc/kI+W+BpqE=;
        b=ytEEgF1j7TRU+CyTlr1OnUOPO4k4ddtDGPqEXKOKwStg2GZX++X8gY+bWoj43zDGma
         aaDJb2brAIcqIWD5gsucnhR2/9XEBFWY9rerrbg0IcTtVmZQWvVnhCYQo/nkK0idZn2a
         /JNlU8RMmk7P5z5WOBJxrF9Iq59ZIcsNcdiA6I5S9wU045r8DShGfxzm/1/ziRBzY/l3
         5QWrC4aeZ4CdpWy76EErwAnwhtpZZRp+hJjmHp916OWPMOggmYOYnYLUsa8WJrNOzLBm
         DCHAW6KyyxHKVAziKl6wbKSI2N8NQK3LRzGBhFF+6BXMVjEP8Y1nr5CYbQARn3QYQkbU
         434Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ldqJT16L;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id qi10-20020a17090b274a00b002347fe543c0si255231pjb.1.2023.02.17.01.50.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 01:50:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id i10-20020a17090a7e0a00b002341a2656e5so614550pjl.1
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 01:50:36 -0800 (PST)
X-Received: by 2002:a17:902:c3cd:b0:19b:f946:e57d with SMTP id
 j13-20020a170902c3cd00b0019bf946e57dmr167155plj.11.1676627435846; Fri, 17 Feb
 2023 01:50:35 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <fbfee41495b306dd8881f9b1c1b80999c885e82f.1676063693.git.andreyknvl@google.com>
 <CAG_fn=XEP2ETd5c8Pz2Eri2mHpDzewnBLWoQC=_Z3VKke9w_0g@mail.gmail.com>
In-Reply-To: <CAG_fn=XEP2ETd5c8Pz2Eri2mHpDzewnBLWoQC=_Z3VKke9w_0g@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 10:50:25 +0100
Message-ID: <CA+fCnZcA8Eh6Bn0_2Jsyjtm=FfqmGk__Rg=3_rudCzG31-JJ6g@mail.gmail.com>
Subject: Re: [PATCH v2 18/18] lib/stackdepot: move documentation comments to stackdepot.h
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ldqJT16L;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1034
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

On Mon, Feb 13, 2023 at 2:28 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Fri, Feb 10, 2023 at 10:19 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Move all interface- and usage-related documentation comments to
> > include/linux/stackdepot.h.
> >
> > It makes sense to have them in the header where they are available to
> > the interface users.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
> > + * For example, KASAN needs to save allocation and free stack traces for each
> > + * object. Storing two stack traces per object requires a lot of memory (e.g.
> > + * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
> > + * stack traces often repeat, using stack depot allows to save about 100x space.
> > + *
> > + * Stack traces are never removed from stack depot.
> ... from the stack depot?

I avoided using "the" for stack depot everywhere to make comments a
bit shorter, but I don't mind using it.

I see that Andrew already added a fix for this. There are other places
where "stack depot" is used without "the", but lets save this for
future clean-ups too.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcA8Eh6Bn0_2Jsyjtm%3DFfqmGk__Rg%3D3_rudCzG31-JJ6g%40mail.gmail.com.
