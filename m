Return-Path: <kasan-dev+bncBCJYX6FNZ4PBBCG2YLBQMGQE5N5AFMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id D118EB0136A
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 08:19:53 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-32b3a3c5cd0sf7277131fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:19:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752214793; cv=pass;
        d=google.com; s=arc-20240605;
        b=USC030ulhr9wvSctorxuFNAbWwWmSSCo+6rQOzsnSKRcY69YMFgNZ9emBU5HGpho87
         xsvw4AyUrLLQW/AMC6kR05k7XRveJFSRmkw1UKJmVOeN+gazwq7Hu7ftOrfuz6L4ZhLK
         PLGF5th/0sgO5hKN8wY/lT9hW4DzNW/mYE54YzebO9y1yOIGuYJW5LBa5z8nhslzEH4a
         RApOKunWmhBkzm7a2FHzDZnxt+0NKk4/zZNMU4W7VrMjmqE/6r9bg3OwpxR1k4x5/xDB
         am3amQ4LGDv4+2+b1uohGERyBjDqF2R65SpS6Tl8nlwoJ7PlAHeyE9uPQZSWQULZo9N1
         jyOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature:dkim-signature;
        bh=S+jqVDxZrmIz54Ainu5RLsT9E1rDP0S7z8DAemaV99s=;
        fh=Z34p2cypGY+w5qxs4XoJ/Qyi6NwzTkhQLv+AXXaso6E=;
        b=QJWsDK4OsY5A1KwZz4asxZxoNKaAd2q3VCqrYRmJjphB78FHfe6zT6/YHlwD/HmcBh
         FLJFndCGPDl3nFrB3SxVU4IFkocnm9eu82tGNqHjHLoCu69nUAjgW++7jS1JQt+4kiGS
         O3jPD17r7hktqwdRpGrYg78/4Li5n9NqrIL0dyum4IvbCsEYfU/vuzmXQbZ08VZbvblR
         j/e4B0a2UCY4VTSNaOn2dmwLdCwMs6zlkSLMWIHfE9HH+uvBpkH/A1oz1HLZQ2m5qttG
         r9v2YoWpDaUUL9JkpLneQ9mmW2SKGk9vLQ34nB+uTPWF7M3o0cgmB5jMRlFaOhRxldGb
         FiXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=URb4c2U1;
       spf=pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752214793; x=1752819593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S+jqVDxZrmIz54Ainu5RLsT9E1rDP0S7z8DAemaV99s=;
        b=L6ghAnfL+YA0SGpNHmIjYK5tnsD0tZqSBrIWoSuPNmsFsEpxsYy/774K2fQgoT+mY1
         BaEXhxza8HRpiAIvsZCQlNGeEjRDyDU4o1wbPVCqmyYxVD6imVIKu3i1EFMLXHtl3Eeg
         KfQWeFf7bXWWWf5+A0KuiSPskbeSbzeX3YpRVX0uQQbhoSG/k8qMVvLXMEGDpoKxBoZB
         i8bARXITqS73BUVCG2Z4d+mhHucnrsjrt4TCNmFT59w5wIWV5lAVvytDEHWcDCK3oNjy
         v8kD60PU+/XxDQfWi2cq+0YoNq4OAnnQF9QapXQZyBjdhFHmRUItyf9ip1Z6PF2A7D/C
         nZ2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752214793; x=1752819593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S+jqVDxZrmIz54Ainu5RLsT9E1rDP0S7z8DAemaV99s=;
        b=RLb7YyOYndJC64Z7dd+L8BIgE9c7M1WqXsz9nHG4G3QVK3R1OZvAvrj+Rh/xmYBs+U
         dS9z4TAgaVLjQBv0dThZtOvXNek9+qFvf3DZqhzjEEJL0sUi1P7aRq3NjfBzoRJMZWyx
         5Hem0WP7xVU8nORMMsrE6h8HaBJeK3Z9fCcVUEP+ZDWQKoIEOxX04cqSo0/pNhF2vKn3
         igRf6bpj01LappClKhgRk9IulxvLfMtHEPKKogKhn8Mo3ZHe7AFtDHH26wcVIdR+QYRo
         F4swaw6WI22Z68DSuu9thfZ7Cq4DKzvzewuSQhcffWRHf0axgIm10DZTCZ5IdlUcUSHm
         ZzMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752214793; x=1752819593;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=S+jqVDxZrmIz54Ainu5RLsT9E1rDP0S7z8DAemaV99s=;
        b=E90bAI2/gnDRNNXCh3MKEuAbS3LUTdfRAsvvELdDXyyPX5pO8Q/c4wslYnabEYKK6d
         l+zxTJSc5bjIV2icrFfwP2fRMQ3o2k743YWqgEsQ4gqWn4Fozt4eQ2XVbhDHg+qOutO4
         wOJQtvUZhA6b9Dka4UhB+FgBD99jEuDYG9u3aTqKDbUyTy1Se4A0ajbH/I90IC0rJ3vd
         jimu7gBRE7gii6AF2sTyYoKqM2NLgpBCcU8zZhCteNTibCoFhEQ4zHzgwE0TX5AgW8Bp
         cZ8BlXJTkL9oNWBX3r1l7uxhbztTHajKDOAy/9NCkI/LkpwcyuccZavagbJS0us8c+Qn
         8liw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWq3LRQJcedLuKPAnsb4zW8CxzVCods1aAa3IDtCJt2eCe70zWPdYyaaAH5uX/II9yFbI70QA==@lfdr.de
X-Gm-Message-State: AOJu0YxVZZbCVUNGRKU9NKzAuir8VQtBiP4rtZw9kEWD0CXK+OiW7OYr
	ZReviPyU5WzEPLFPH8UhAZXrmpuTVgUEYktfq1u4WYGL9nbByw7Rbwt8
X-Google-Smtp-Source: AGHT+IF3j8oNyje0seodxg+1b5iDkJSQPiYyDVmEMkLlmqhLuTF1OM87EDWfb2pm2NRhI2GA39O1Bw==
X-Received: by 2002:a2e:8549:0:b0:32c:a097:414b with SMTP id 38308e7fff4ca-3305346ccf7mr4056741fa.19.1752214792638;
        Thu, 10 Jul 2025 23:19:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe8EEJIHR4dMFmvpPhrrr5Ikn9ZUvCeY7ERLWTJm5JrpQ==
Received: by 2002:a05:651c:304:b0:329:947:b67d with SMTP id
 38308e7fff4ca-32f4fc3e8afls3677271fa.0.-pod-prod-03-eu; Thu, 10 Jul 2025
 23:19:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqoyysybToB5tMcKysOtlEVe8WcbjGCvx77g9wr8rrOpLeGf0mWJDYS0QqzmzrMRgZUJ37r/pQ4Gw=@googlegroups.com
X-Received: by 2002:a2e:b8cf:0:b0:30b:a20b:6667 with SMTP id 38308e7fff4ca-330533185d2mr5869041fa.9.1752214789408;
        Thu, 10 Jul 2025 23:19:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752214789; cv=none;
        d=google.com; s=arc-20240605;
        b=SDo4m7OqXbRNl5z4FcvfyiEEf9wVGyoy1sEtAPQPD3v3rsB9CL9C9QQIA7XU5uSr6K
         B6jaY1NgKnk7xn5dOUDixoX7Bm39ZQ0NybyLrxbT5kUXGn9c4ZbHllCGhDiyY//sUGL4
         HTLotgzkuRUZFEOqh9gxZeJOCMkCk5y78pZtUg8+rdmXB6hEcoA3k2/J5nopDsanGLRS
         ezOk8AYpZQDOzXeff1UVeFM/wP6tkO6Ifcw8bl5Qb6I9uXxmnUb4XB099BHPWiG2Zb8r
         qIB/5D4tiJeWNVp0/zlGJhy1eRfyoRqKp50P2rSuzzbkeKyHRZA8bG9fxi2z447icFqJ
         ysCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=tVh9hsjl81v4ae22eJ2co4oKHaNUT7Y20uC96jCSTXU=;
        fh=v8SqeZkb0+8zeiOYsAb1jzwLcr/hX+jFecZQsgBJvso=;
        b=I2oTvYsidM00UhJCF2w+Q2T9w/NNmurvdU+CI7Jk2TKcG3XRPJdzt4JBAdDOmKYqQR
         SGY3OW7lsy9kffWCtX/UbN11ote14AcsUK19MQ8SL8B7vOpcoV7DfTtF23trHrF5oFZE
         0MlAP1cBmZK2l+69UYIAdk4nl0IltlFdhLU0FuLyjxGv6y47XxGHgUu1HJ3aHYYRXFHv
         +hauvlcTi+OoqEqU/GPbrtG3ogyccDGxa4wzYG/20Mav2N3KmlD4cBqVgj7fj8XIbxPe
         ytKuN1HViIYOWIMIyDXmHRmPaj0rftfm8Qu/RS3CgBCY2BQvMRIWSbhI9Q9k82SH6BvL
         n6FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=URb4c2U1;
       spf=pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fab84abcasi627761fa.7.2025.07.10.23.19.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 23:19:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id ffacd0b85a97d-3a50fc7ac4dso832438f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 23:19:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU1ej3a6KXpA6Z/zrI28iwRJvBlM/550RXzUzywRk2jmm6IjNoWJl+tswWK6VevG5i6s6Nzh4FMRPQ=@googlegroups.com
X-Gm-Gg: ASbGnct69fPJNSP6pBUEvGOLffMzZbAUJUPPPeCpLIpTKkPJDSTPCCz8OVS/05IlG1A
	wnApCJsu4L9TjA6yxTzZq5EDCg38iNcGLJZG6hcddTw0f8mDf7Bx0FcZFb3Th/pERxpSRP6oWgp
	OBmKrm66oRfq7Qr+9JpAmJMwG46CSorTsMdr/fFj6ATIiuY+b6j57Jta1owZV4dec/1JKVkjIMy
	yTgvRRloq8APuINTzy/CyO7bi8cK58yyWPKcgX5PviKd2iGESYe8y8DUVTpa1ZMA8z0Xwrb+xSJ
	GJHFGgxZEyl9j6L0pLBNC84e64fkgtPZ7L7cxiLbQrGy69wIM/P+w/7YnzErcHO9M0IWHJHs50H
	jeXJn8V8olVQCTKrFlqgYCbvN25WHlwvvAcV78hqGe3RSHSG7jSMTERK/jng4mro90Ijap/rh8k
	0MkBDRiBODryVRXus5PBBloprBdCnQcIzK8WXalpchtTMexAE1b4qQwYGUxRTk4QH7phcSQnL1a
	fUahzLcie7m8/xDJ7s8vJGyzmhM1kE=
X-Received: by 2002:a5d:5f52:0:b0:3a6:c923:bc5f with SMTP id ffacd0b85a97d-3b5f187ebaamr2048139f8f.17.1752214788443;
        Thu, 10 Jul 2025 23:19:48 -0700 (PDT)
Received: from 2a02-8388-e6bb-e300-2ae5-f1e1-5796-cbba.cable.dynamic.v6.surfer.at (2a02-8388-e6bb-e300-2ae5-f1e1-5796-cbba.cable.dynamic.v6.surfer.at. [2a02:8388:e6bb:e300:2ae5:f1e1:5796:cbba])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b5e8dc21fdsm3608080f8f.33.2025.07.10.23.19.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 23:19:48 -0700 (PDT)
Message-ID: <bf3eb247c98cd96c602653bbec8c8e34a8c718ec.camel@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
From: Martin Uecker <ma.uecker@gmail.com>
To: Linus Torvalds <torvalds@linux-foundation.org>, Alejandro Colomar
	 <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, Kees Cook
 <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow
 <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, Andrew Morton
 <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov
 <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver
 <elver@google.com>, Christoph Lameter <cl@linux.com>, David Rientjes
 <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin
 <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, Andrew
 Clayton <andrew@digital-domain.net>, Rasmus Villemoes
 <linux@rasmusvillemoes.dk>,  Michal Hocko <mhocko@suse.com>, Al Viro
 <viro@zeniv.linux.org.uk>, Sam James <sam@gentoo.org>, Andrew Pinski
 <pinskia@gmail.com>
Date: Fri, 11 Jul 2025 08:19:46 +0200
In-Reply-To: <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
References: <cover.1751823326.git.alx@kernel.org>
	 <cover.1752182685.git.alx@kernel.org>
	 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
	 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
	 <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.46.4-2
MIME-Version: 1.0
X-Original-Sender: ma.uecker@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=URb4c2U1;       spf=pass
 (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::435
 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Am Freitag, dem 11.07.2025 um 08:05 +0200 schrieb Martin Uecker:
> Am Donnerstag, dem 10.07.2025 um 14:58 -0700 schrieb Linus Torvalds:
> > On Thu, 10 Jul 2025 at 14:31, Alejandro Colomar <alx@kernel.org> wrote:
> > > 
> > > These macros are essentially the same as the 2-argument version of
> > > strscpy(), but with a formatted string, and returning a pointer to the
> > > terminating '\0' (or NULL, on error).
> > 
> > No.
> > 
> > Stop this garbage.
> > 
> > You took my suggestion, and then you messed it up.
> > 
> > Your version of sprintf_array() is broken. It evaluates 'a' twice.
> > Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
> > argument.
> > 
> > And you did it for no reason I can see. You said that you wanted to
> > return the end of the resulting string, but the fact is, not a single
> > user seems to care, and honestly, I think it would be wrong to care.
> > The size of the result is likely the more useful thing, or you could
> > even make these 'void' or something.
> > 
> > But instead you made the macro be dangerous to use.
> > 
> > This kind of churn is WRONG. It _looks_ like a cleanup that doesn't
> > change anything, but then it has subtle bugs that will come and bite
> > us later because you did things wrong.
> > 
> > I'm NAK'ing all of this. This is BAD. Cleanup patches had better be
> > fundamentally correct, not introduce broken "helpers" that will make
> > for really subtle bugs.
> > 
> > Maybe nobody ever ends up having that first argument with a side
> > effect. MAYBE. It's still very very wrong.
> > 
> >                 Linus
> 
> What I am puzzled about is that - if you revise your string APIs -,
> you do not directly go for a safe abstraction that combines length
> and pointer and instead keep using these fragile 80s-style string
> functions and open-coded pointer and size computations that everybody
> gets wrong all the time.
> 
> String handling could also look like this:
> 
> 
> https://godbolt.org/z/dqGz9b4sM
> 
> and be completely bounds safe.
> 
> (Note that those function abort() on allocation failure, but this
> is an unfinished demo and also not for kernel use. Also I need to
> rewrite this using string views.)
> 

And *if* you want functions that manipulate buffers, why not pass
a pointer to the buffer instead of to its first element to not loose
the type information.

int foo(size_t s, char (*p)[s]);

char buf[10;
foo(ARRAY_SIZE(buf), &buf);

may look slightly unusual but is a lot safer than

int foo(char *buf, size_t len);

char buf[10];
foo(buf, ARRAY_SIZE(buf);

and - once you are used to it - also more logical because why would
you pass a pointer to part of an object to a function that is supposed
to work on the complete object.

Martin




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bf3eb247c98cd96c602653bbec8c8e34a8c718ec.camel%40gmail.com.
