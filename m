Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB35OQDYQKGQEFJSFUJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 60A7613D572
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 08:57:36 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id h130sf881474wme.7
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 23:57:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579161456; cv=pass;
        d=google.com; s=arc-20160816;
        b=EIzfaZaLK1Ns8lJ9WSjHndRL7pjWVKEmFHy62ELZRsMAdthl+1scr75QRwGrck8A2u
         bF0aWkewuLCJagzz/teYsjE/VkgAhTx/v7Uk82DdFVEM7NZ/df+Q4Q6m9iwj7nQziWve
         awpH4WFvX/s3TsKqJCocalQlGLaMoU7Fpt+1bG+XEZgFOaYa4rK7kqAyTAudQ6xNxmhF
         QaDh6iqQEKvp5BZ9d9fh8WUFEXcR2oygXSx+r7qElHfItxe+vueaFCK3BXnd+815SZpI
         oQb66FUr9ns5Lb+82rYpqVzKRhwmNjqGrewY4ACd0nszNTLxIJEUBOl8TPzVXMCNl4Ox
         sWsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=ED6IwzU6yZSug2jJIpDlVEp/DG2KvxO+0ERGqD3yDEw=;
        b=kz8EJifVj2tkI8jjKK0fS3CNQWlzl93jQYnY8CVJmoT1XKwqN3fEWQIdhWxTQJUULr
         nyjQVBGxqwINdJCJA5pKYP0qtI5MeLCktcObIE/DoniKus5kmWjQxYZ3oj1kfanbyNrU
         ypmwT+niXbaKn3Z/nTta2/riLskJTWfVhteQc56x5MF6ZkaCAST4grE39O/ValO4jG2o
         KePWHfB5TjtBKeMy+BRThrk/rgtgQFMJhXFadrTJdgHQvArEzfEiT+2Ld8BnFlEna58w
         FYf4IbwfT9YP3HKplbxCqxjKDkGVOATh64oITlv8rfcbDvEDHcoc/r909GonphEqCnP/
         t8DQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ED6IwzU6yZSug2jJIpDlVEp/DG2KvxO+0ERGqD3yDEw=;
        b=iy6SsghIa8eGmIo+GTEZCUafQJlRMZPeDMkWCm5Q3QBm9GqP/KvOFzbu8JVp/CSXN1
         Qghu2pk1kqz1FGomgvwleDum/L+7qbBGcVG2WXsCl3/FaZHkfTzk9em5Xrmu3O/dKnwY
         Sp6eYBqOhdaQyikBmJzWLTQObF10rd943XEPHxT9yJVQELBmZ1Rt1FkCEOtgvulcQ6DQ
         O6ZaDXOsftfwf23gEgPwasCllUjQB3Bf2ayyZ87mXjNGPInc74Nbu4HIvC1Yzkq1//XH
         DnyG8JpXd8Ypc5evr64yJOkEuX3M0geDbB7qGErgVE76lTkYNuNW0CWxBQ38vzX7j/+B
         QiZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ED6IwzU6yZSug2jJIpDlVEp/DG2KvxO+0ERGqD3yDEw=;
        b=Gh9OyKQ9NTrmKdxXz/ErFR9mxuWs59fJk7jQLZJ3kGcFurSTPmc8RQad3Ls6mtM0UU
         HEBCvnKOLKjgI7cmh0grUy5LN5KUF+Jy3HhO5hKG8/UF8eF1VAZ9peq1Raz7pXy5T1T0
         bN5ht+wL5I1Cjr884vc66cktjw0x3+FffKZNxvwsJGIm6Fz4m9VnRZxJPxPWUD45FoEw
         p0NvkufBH2btL3bXmpfPZ0WYxpcQr2+8CdaSRpUJnB2goKT/GX2r0wPr6fmyG+ZY69yM
         Cy+KnMCtKT134SnLeAo3TX33c1jkCyy1RP5e+6X9184uA5mxACikMugkwCtCHTglLBmE
         Y97g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW3yxa/Bw8k5SqJk0LCcpx/rsBAqQkACEK5i+LfbVSi47vkRWdp
	XhUK95SPvfA/nI8GfZf7i40=
X-Google-Smtp-Source: APXvYqxO3sbDbkJdwHGAMfFYX/fOhYTBsjQyw0BfdWlZCCwArij2IYD6MSHN57H9UQgobLDmHVFzyg==
X-Received: by 2002:a5d:458d:: with SMTP id p13mr1873985wrq.314.1579161455993;
        Wed, 15 Jan 2020 23:57:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c76b:: with SMTP id x11ls844157wmk.3.gmail; Wed, 15 Jan
 2020 23:57:35 -0800 (PST)
X-Received: by 2002:a7b:c38c:: with SMTP id s12mr4672113wmj.96.1579161455531;
        Wed, 15 Jan 2020 23:57:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579161455; cv=none;
        d=google.com; s=arc-20160816;
        b=qGVX+TVnXQK+SgaoPBTbXdVBR3wrNujUlDbnmg9Dgn14VSk/uINnyOh6m+B9Pzw4G+
         rI7dHs0/BbCo2/Y/Ht0zB0UFa5vc3D+B8osjhWRlN1pKsIlyLuCTjKUOhAH8nKb7oVRK
         sWoDJE0J/fxpZiPtL6wYarjt5Hz/5YFjbeS6hxqt5AWpijfUkqjYYK9zxzKpBX4Q2A/v
         nhIMecG/cC5qPnKNRPjYpmhaXz32wZMn5PFqpNjqHlQb5XLRb9bBkrMO/pt0368/q91T
         R0Djx0a9O+Z5PM7ltX0lbrI4S+LpB4hXK976P1oiTYI+q23LaSI5SV6i44IB9Wqif1iJ
         LUlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=ao4Y9gZiexavvmdXP+FAoZZy1s84ZmeB58AHmou+NbI=;
        b=X4ZWFv53ygFHGnWFiiAWZE6TBsSSZvb49VJnx+8J2wuB3+UKRXL/uHTRiaJ3uFBD4L
         Kri6r0+vFxldpAjxTH5UMX0aJgVp4wx6krjdjx8yTUv0btgIaxL+soOZMJrvgIEJVHJQ
         Mrgd8wrkqqBFNw7gSFBnQSQMlUskG35iKmvYPYJBNfXpnhL+uoMIPKX+Y3yopITBQT8t
         3+YaaqGXTqHOBd4jl0UvKVIDr8z1Fqgggak3XOWRdY+Zm8Gso2clUeMjW/WzPGUqKiFf
         wtA2QqaTWlcSyoH4vIwDlS1cmjguHWHDsONfcNNLFlUuWNHRPvT1wVp0b8vQbR7jL15E
         1Hxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id p23si115257wma.1.2020.01.15.23.57.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Jan 2020 23:57:35 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1is01s-00BVg7-C7; Thu, 16 Jan 2020 08:57:24 +0100
Message-ID: <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Patricia Alfonso <trishalfonso@google.com>
Cc: jdike@addtoit.com, richard@nod.at, anton.ivanov@cambridgegreys.com, 
 aryabinin@virtuozzo.com, dvyukov@google.com, David Gow
 <davidgow@google.com>,  Brendan Higgins <brendanhiggins@google.com>,
 linux-um@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com
Date: Thu, 16 Jan 2020 08:57:22 +0100
In-Reply-To: <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com> (sfid-20200115_235651_948442_0F0A0073)
References: <20200115182816.33892-1-trishalfonso@google.com>
	 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
	 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
	 (sfid-20200115_235651_948442_0F0A0073)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.2 (3.34.2-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

Hi,

> This seems like a good idea. I'll keep the #ifdef around
> KASAN_SHADOW_SIZE, but add "select HAVE_ARCH_KASAN if X86_64" as well.
> This will make extending it later easier.

Yeah, that makes a lot of sense.

I think once somebody (Anton? Richard?) start applying patches again,
they will pick up my revert for CONFIG_CONSTRUCTORS:

https://patchwork.ozlabs.org/patch/1204275/

(See there for why I had to revert it)

If I remember correctly, KASAN depends on CONSTRUCTORS, so that revert
will then break your patch here?

And if I remember from looking at KASAN, some of the constructors there
depended on initializing after the KASAN data structures were set up (or
at least allocated)? It may be that you solved that by allocating the
shadow so very early though.

In any case, I think you should pick up that revert of
CONFIG_CONSTRUCTORS and see what you have to do to make it still work,
if that's possible.

If not, then ... tricky, not sure what to do. Maybe then we could
somehow hook in and have our own constructor that's called even before
the compiler-emitted ASAN constructors, to allocate the necessary data
structures.

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f382794416c023b6711ed2ca645abe4fb17d6da.camel%40sipsolutions.net.
