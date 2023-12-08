Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEOBZSVQMGQEUDIQKYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 56F9380A4D8
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 14:56:35 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-58d336d8f91sf2350986eaf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 05:56:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702043794; cv=pass;
        d=google.com; s=arc-20160816;
        b=M2xrLcttqIH04EBW1d5efgkHA5d67RuKpD5vqKbdwwQoDHgTKf13dhya9/JPsBTCtx
         RtA9PChdymLY8vkKA2MJwPxoy60t6LXbqfJpLkhoFdlimnjK9COFf3lLZIlXCWzEtjrd
         j1Z6EJpep5bPCLgpZIXC0Ra82yCNyNOEMa98K0Q2HFzFqGXe9v1t5OOlYOd8DmCVsARC
         uopI2M1ULTnUDcgO2U8mT8FHGDtPVpOttRdBtuEhVC7lkwae95sLkBnll6ZcbSz38JST
         F15hNA8CFlfNl3GK5fNwMf7xv6INI3ILhiRgRcqVUHUMdghD0fYFmkucvWEePAjBYIJO
         vxgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o4lxEm1oVby5kw8tGu3u3AdTdm1qBsp+UEJ6VvA4kTE=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=cVS6SfRT6AtV6ZS8CFNw3u0GCTM0fQCp0NEEHcRUC5LuZLvLPOAHJPAmBMigjuD6Bz
         Q2pVMJWYS7hOH3nfTvRVVUan057FCOcXOyGuAEaW7JsNN83T+xvrPZp9k5ZpvQYZAs3m
         kbZ7FAcgvEdf9Fgniui7gBIqG08x6OYqmR3ostJ93kPYK/3ghkSShP2q4304VNTNGGQZ
         iwcr4uRXH/lGvzMI/IBEq97zPHwnxtW0b+3ZmQn1mlgBvo5IX7G2Kr20Zc/lVuA6FJuj
         5JbrqorjisYKtsGxe0yk0209utYfIt2REKemnuED8eBeh88CavyejzDerbGQikfGhMzU
         s4rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=snf2OG+G;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702043794; x=1702648594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o4lxEm1oVby5kw8tGu3u3AdTdm1qBsp+UEJ6VvA4kTE=;
        b=WtzHudhv8/LOHEKHqu2tFpLRNBDC7/jRnzyOSn5+W0cuZjj8tfmbKWHlPC10NgX3m9
         m9VfDZZUigz0EFjdwhB8xVXQ4uWgMPhy0bSyedDSU6pJvV7eGXg29+yTfNc18MWevIZj
         lb2RIjstniXGEUQXr0K4xlaFNfmuDgN8w/xeSzgApINTcK3NsAD88Hq94KJax4Gp/yEZ
         9+OmNEw2ZYoATT3OTldpS9JkM6bcBxT8nPFb07/ZaZchgfeJpVHqysLlaaFB6xnfcvbF
         PEGxDzARonARBOOkgkh/t++6AvOS1Cls0eY+x4SALwXrfw9vsUwKmWQnkfTM0cbSV0/8
         8zqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702043794; x=1702648594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=o4lxEm1oVby5kw8tGu3u3AdTdm1qBsp+UEJ6VvA4kTE=;
        b=T2bnuXh1E/gD8Kp7+0VZVnpwxxQjklIiGeTnff+jxuU2zbwDXo67ybk2bKpj8EoGy4
         ok6ajg6Paa9piisyVN51vehzo7PFysZPiijQ8lfhA435jrZZqM6x7eoWdvpTNG/vGL2j
         d2hPq2HGKt+cmag9CzKecgKLmEbyczAEmGtreHV3uGZT2mM+ermPRje6DiOR9bqeGq3V
         yuyFFMir6qD8yvdpDI5aClXF6TKk8GEKJ05sGvBk5fbJ0t6MPNQGA6ZpLxNtBNNo35l9
         5nljz3yoN30HSPyprbZtOpLZimDJmqvtMjGRbezyio2Bmdnwp6jiazigEkRKDFFfvVem
         OzTQ==
X-Gm-Message-State: AOJu0YzBnwbqSz4jMhgcrE14++jwxnqgOBcoavb4v7v1XrqH7/x6GdQ0
	iNEzaJCnSMqtZP9ilS13bmg=
X-Google-Smtp-Source: AGHT+IGmCIPlvFwvUVI2sqZHhhp4TUXwuIzLtgwjDpIHh3PVoDKRuSTiAZwPEEHs/2bIjy2kxkMpgg==
X-Received: by 2002:a4a:55ca:0:b0:590:67db:1dcb with SMTP id e193-20020a4a55ca000000b0059067db1dcbmr101869oob.4.1702043793759;
        Fri, 08 Dec 2023 05:56:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2224:b0:589:f297:6025 with SMTP id
 cj36-20020a056820222400b00589f2976025ls1700556oob.0.-pod-prod-02-us; Fri, 08
 Dec 2023 05:56:33 -0800 (PST)
X-Received: by 2002:a05:6830:1d8a:b0:6d9:d132:e047 with SMTP id y10-20020a0568301d8a00b006d9d132e047mr68406oti.31.1702043793034;
        Fri, 08 Dec 2023 05:56:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702043793; cv=none;
        d=google.com; s=arc-20160816;
        b=AqvrxWf5dkL1A3N5vjYwkWxcmAfyp+gVkapscuo5EsMY/EFPL0qI/GQKeB9lk9N+Eb
         /x9Z/+7Ti3kv4ze2S2CuUkgT0JAzKe5g++sXzMw3kRR4r1uArGoZ0wYOPQA1wrYlr1wg
         iKBlC78vWVRiNp2TaH47BPWoWVUDdXtd2GKVIBWh/9WS8fw/cLY45cWPG6YuzdlJzumw
         9niafDgBMBLB9wv/8wIAjZf2V6i0yp9r3HziVwYitUJxfi1PHMxUaZFUN3ytMJvULcMh
         ma3NGn2OPB2kqmJncmJZt2fa/p3D1x1Tb8GpE52KYfBikqKt7YVHbyko7i9ilqKeQRCb
         toRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SlUqBCSJE7b+NOWHxQNrRwEhp2gTAvY03mAPrdADOdo=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=wsuOSJBR2gBooa5jAOFB5w9NEjIvbDGHMX42DPK/j7sJjB4GCfgnuP5gT3JIwECEgk
         e7GdLgZxGQpc+a8g2PXlfdOlZjNs6FP11An1+mEZoVHBE5joOPkFbLqbRA7o90vIat+V
         kBJAfB6KW9y2MkCxkCBIFIfhJrKKvv0hsFz54SASMlf6DGA0PJvMIcC9vxlNa2eZKhN6
         VhgG7wpOgWU0YvMXi7Do1nvWCrsD0ZU71qnrIBwGv4Fphl9AUPrIg/AbVq26dYvlDleK
         eLL7zGfz/S/YkALuvmmGIRe7GMgqjAana8YWTQtnFjKQ1hz9v6GaniyGN8/REcG1Jh2/
         JfIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=snf2OG+G;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id i39-20020a056830452700b006d645ea12e0si167517otv.5.2023.12.08.05.56.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 05:56:33 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-67a894ccb4eso11808746d6.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 05:56:32 -0800 (PST)
X-Received: by 2002:a05:6214:5802:b0:67a:a951:7fc2 with SMTP id
 mk2-20020a056214580200b0067aa9517fc2mr4258051qvb.119.1702043792410; Fri, 08
 Dec 2023 05:56:32 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-18-iii@linux.ibm.com>
 <CAG_fn=Ug6MFyoj=J_yabfd-V+3vGYNS3-CS+fhW9Tsc847xMtw@mail.gmail.com>
In-Reply-To: <CAG_fn=Ug6MFyoj=J_yabfd-V+3vGYNS3-CS+fhW9Tsc847xMtw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 14:55:56 +0100
Message-ID: <CAG_fn=XbDFa_7BWMzR5cVEVp-GuHxK2fyFAZJgXqXb8qL1ZhAA@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=snf2OG+G;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
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

On Fri, Dec 8, 2023 at 1:53=E2=80=AFPM Alexander Potapenko <glider@google.c=
om> wrote:
>
> On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.=
com> wrote:
> >
> > KMSAN warns about check_canary() accessing the canary.
> >
> > The reason is that, even though set_canary() is properly instrumented
> > and sets shadow, slub explicitly poisons the canary's address range
> > afterwards.
> >
> > Unpoisoning the canary is not the right thing to do: only
> > check_canary() is supposed to ever touch it. Instead, disable KMSAN
> > checks around canary read accesses.
> >
> > Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>

and even

Tested-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXbDFa_7BWMzR5cVEVp-GuHxK2fyFAZJgXqXb8qL1ZhAA%40mail.gmai=
l.com.
