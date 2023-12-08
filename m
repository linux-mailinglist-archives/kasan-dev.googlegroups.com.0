Return-Path: <kasan-dev+bncBCCMH5WKTMGRBANEZSVQMGQEED6JN3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id DBEB880A3F1
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 13:54:26 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-35d7256aea9sf1073795ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 04:54:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702040065; cv=pass;
        d=google.com; s=arc-20160816;
        b=OAFKWaE1pgZ+SqLu7JVttZ0nCNoOQy/hWlh8P5dPpx4H1JR5ruwAygcVaEbPucHLmr
         E2aNv/9YZrz03LT5npTbox98IXAw9IqgMUw+Z6a0QJDD9/6+hG8f98iOQmsRbdymn0VS
         KKqMn2PDRb/yHFmjW/mBKR3f9q33auloY6MzWBHHccHpNPgc7rE8dvztnQonRhH6lNnb
         3yzASKPl40o7mKp2jZXeCcjdgXwXuJwDBJX5QCZIxLiF9lVoR6yLppAZnQ1aOkdVHiMH
         N3vm+nPvXONjWaa08hHqTx8ufYKkgEoCeiwsW6m3xUdeq5vHzCMmnmD4dOX/HwyAfT2F
         YS1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+Cpzi9buhzaxwK7vF36jDnEtb5xJCY4eE9+HKrlec9o=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=p6gCUbtKO1MfS5C1+kHGZ3jp9piDzv16lYayTkUWPzVvFQTQz31l0RdwZ1Kvp77dJA
         KXRQFLaYTW/YGmRghYRPuwsKHMDgtUEXijUnMsA0Nk/r7sBGS6tu+7CowC5H2TuARgWw
         PJbxGbUmJXIAz1lSoVoXUZ3vYSyDoUFbuQMj5GM6E9VXbCVGPSTJPSMEJDxgS41UHz0v
         hiLe5kh7cbQKUMEiY/33dsmoh2P6lWb8CM6bu4RR8zuY9EKAfsifbRieSN7gdG0PGLxl
         wXf5oV+DSeMFMaoy9Qp/0eOIS/6Qg85h2haISj18FkBxuBnP4PlAJsfwFZ4ZDhwdR7ZN
         ZQ8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wRDYH8uN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702040065; x=1702644865; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+Cpzi9buhzaxwK7vF36jDnEtb5xJCY4eE9+HKrlec9o=;
        b=Wi7t9tpyaQ5uxtIM02opLomMp4rN0w3/OXzGeRVpGsXb7KpbJxUxlrF+8zJDhPvcS8
         KAoBsXcB2Nhts4wUdO/JR3Nns+NMeIautbVnxf0bbRM9VZ3aezyZ84fa1JID7poQD7f9
         eTv9i1yT1yNa6EzFy3tUlRhFa/7jleq1D+87TiUTYcnFgJasYWb9jALC+Y+P1H0XDT+l
         t5YDFnIUUladYeirZ8DnmD7AFlUNIp+VaQqxpAQ+zgr96bYST4oi8ki7tDq2ymwWxzae
         7nfGF7Gk7axsRZCU2hyI3bNXxx2Qn52VXr9rfhNM5uWBc1zvUNIsltUwU0w1g1kk+fzU
         N4zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702040065; x=1702644865;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+Cpzi9buhzaxwK7vF36jDnEtb5xJCY4eE9+HKrlec9o=;
        b=WTdlEsvPTfpIBHL6SoFJU+jiheGnIPk6KrpAeFPhFETssjbNSKnugvLGJJfIWWiwDa
         ytX+kKruCMXl2QFKDkdeAgeOT+/lJafd0GFzjhT3MG2gkw4Aas5oGASiUgT83BiqXS4b
         MSd+33s6bk81Df81X+2gg5zSIPlTp0J5G9addwxhTr5Ad1TotZgdSPwcCInRA60aTUlX
         F02awmYkR+qMQO1dV4f344USKuvjw/HYe4I1IwGBkUor+31S/yQNSbL++F2JJGtgdcyH
         vzrKIzD/XIO2jaiQVYQgQEyKZK/j9L0irYl4SqMkasvCkJ5dtZrfVxE52jIGgf7mWFeR
         jO6w==
X-Gm-Message-State: AOJu0YzHiie4SPq2u7Qt1jo6/Wc26oljUYWsYjhk419rtXZALaByF6uA
	sN6ijwk7Q8zRXPCmpf7dUBk=
X-Google-Smtp-Source: AGHT+IE4Hg561hGhFe6QRRV9KTaUeDLCP2IbmToKrsTbywAYBTVnNjfAoaHn7zHAUeRu+6AMDWQ1jw==
X-Received: by 2002:a05:6e02:11a2:b0:35d:73e5:37e5 with SMTP id 2-20020a056e0211a200b0035d73e537e5mr111948ilj.25.1702040065389;
        Fri, 08 Dec 2023 04:54:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:602:b0:58d:ed89:f343 with SMTP id
 e2-20020a056820060200b0058ded89f343ls3596934oow.1.-pod-prod-09-us; Fri, 08
 Dec 2023 04:54:24 -0800 (PST)
X-Received: by 2002:a05:6820:22a4:b0:590:16e7:d767 with SMTP id ck36-20020a05682022a400b0059016e7d767mr24439oob.3.1702040064579;
        Fri, 08 Dec 2023 04:54:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702040064; cv=none;
        d=google.com; s=arc-20160816;
        b=LnlOjygNME7lp4jTa40FIf5oHAqaZzOHeVvl3/wqf1aUStLudqmAZP+T0FChxjYAqb
         9VVg5NXDc9ash13UETvk12BtcV5VhbJSBA2LpM5lUSlphGEQyHm/JKuNdgmQNFcbb6iD
         MoLfU2DqcRK6C4HzhLHu0+nDOj5Za6jKv4Sht0XpakPP2A6aICqLUbJfNmgDOeJH5mNP
         cO0BCIdwgbqPgWYZ2DMfn+E41HIJXj/hm+ICm/f+50VI0PdMmsegeFd19XkJLu9qVWVj
         F8St6hcM328AfXHM3eTz6LGVhSRw9vvmKiQNVTd8M15zqNgiCc7aJ/GGp/6ZhkzShLcQ
         G/JA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ByI2BmM76fDl6CBfV37McPabf7tQNlC2zWfp5P+Us7w=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=AdEEQa3kYUy76W/gn6uAceKwYRLpNiti+YjdpNwSXPtccZ6kS67P8TQ7KX1SUVo7Jl
         6/BRncZ/ppnEieJlyHo/drfJNHmN4Zot3Rzowubh7UG1zB1mLQj1sH5NnfgLsmp/hPnl
         CMl1eoYr2XSdA1UrsHJyosSpmUf0R8Ug7A8jpXXnoHx8DXIil8aQthrY9ZanUgiT1m0n
         ZE2hxlcZJ2gcPteJp90SZGVT8hqXfwVzyBZ5bt0ecJQhMXLUyhSu1/eZy7wJeMuJOODs
         9CDAfjSwKYr/oWAnJFdyxvp7H1iTtkI+6RsHBszm6XiWG/ZzAEC9WOPHajw0cSR2NhA+
         9WrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wRDYH8uN;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id bs8-20020a056820178800b0059090fc9cfdsi33525oob.0.2023.12.08.04.54.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 04:54:24 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 3f1490d57ef6-dbc1efc23f7so2084037276.2
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 04:54:24 -0800 (PST)
X-Received: by 2002:a25:2395:0:b0:db7:dad0:76dd with SMTP id
 j143-20020a252395000000b00db7dad076ddmr3075741ybj.121.1702040063846; Fri, 08
 Dec 2023 04:54:23 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-18-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-18-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 13:53:41 +0100
Message-ID: <CAG_fn=Ug6MFyoj=J_yabfd-V+3vGYNS3-CS+fhW9Tsc847xMtw@mail.gmail.com>
Subject: Re: [PATCH v2 17/33] mm: kfence: Disable KMSAN when checking the canary
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
 header.i=@google.com header.s=20230601 header.b=wRDYH8uN;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> KMSAN warns about check_canary() accessing the canary.
>
> The reason is that, even though set_canary() is properly instrumented
> and sets shadow, slub explicitly poisons the canary's address range
> afterwards.
>
> Unpoisoning the canary is not the right thing to do: only
> check_canary() is supposed to ever touch it. Instead, disable KMSAN
> checks around canary read accesses.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUg6MFyoj%3DJ_yabfd-V%2B3vGYNS3-CS%2BfhW9Tsc847xMtw%40mai=
l.gmail.com.
