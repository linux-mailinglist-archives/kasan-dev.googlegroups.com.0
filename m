Return-Path: <kasan-dev+bncBD6ZP2WSRIFRB3HLYCNAMGQEXVLSJMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id EA0E6604EF7
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 19:37:49 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id cf15-20020a056512280f00b004a28ba148bbsf6101311lfb.22
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 10:37:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666201069; cv=pass;
        d=google.com; s=arc-20160816;
        b=GIb4SsKVyjNUejRfF6n1YSYmP6xtkjkcNGD0hUKhoyZqk1jgx/CcqAk6eh88RwjcAH
         bLHagBeOW9fObEpJjzpYMI7aoVcviP7xBBhQOFCuqTj38p7KVh6b+fBfI47btYXvCWWp
         Ky8uHvl0Rm6G8Ehr/F4wYKBZuUB8z0aR7ZSw5HarJ3WNVc6PO3ogcfD76wVTCf3cx+JJ
         WwQV7+wdrfHiOW+PsTlIzq2vCcRiI4ZonUZqEkVnurMhh130AVv7i7ha3Rp8Lw95Zp0m
         pCFZZc3cyaxG5fbs9ika0SJLDI0aGbf/vmAYxrxyJ2mNaXLvBUiiD7u3R0P+GM3RwqFd
         jGoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=l4YYQ/GEOmvtTjzStYo8x7IGwbwCnW38Ss/qOzCy/CM=;
        b=tNcB1p+75urxdcbqYCPcx9uwcukPHa1FU4e/tBn4azs7QwubGz3QdgOgkUSgTlGgXQ
         dE3KY2WFHmp89GEf0CqgEnfRtaBmAG8KUVidwFMHFCsMedgNb+ePKh4oZOR4KxBtTMNo
         zLAfO4yjWdTfDly07YhH/Mg8bM8cbc4EwEf9paNck7fLNPHGD3jr+ElS8rBz+rg5HHAE
         h40GjFRj7j/NDXKkKtvVZ9gnVFOyw9HdtWmH5dFFk5kULJ2EpyuX46VetiWRITAGbQZj
         +PLkmLUWuIMq0mqnWiRa32D1/b8aj3NFSiaDFJTXonyW9TcASztp4GuE4NfpO1hsQGxN
         OOJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=MEjHkmlZ;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l4YYQ/GEOmvtTjzStYo8x7IGwbwCnW38Ss/qOzCy/CM=;
        b=NmXDCnekojSWqvNHYwhLLAZxt7mxMyyPQ0rYX10O580bzScgIH4hRplxRKkv8QwAdz
         RdVFpGBr3ioEj3A/yFZEfbmMlSmi3tPsUTr8DPlWv9z8PCG4EAGv9005tix7Mudi1aEh
         s43FdveUHPOIN2hdfJ1yCp/rsDQXWJ8SylMjBcUai6lyXb+JqOwMbiGNzIzrzR+csJPv
         QX3BVD3fZJmmDPTgakuBLLcC7dqZ+HPrX2wq4GQpH2xEDiIF0wUmVdqSnjRpekDyDcZH
         j09FvKUAqXFmFbFJug5zKmvyAf+/BThdLQBOO6vVHc5fp5QyAhrS66sFNaVVPM2iffve
         Sd0w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=l4YYQ/GEOmvtTjzStYo8x7IGwbwCnW38Ss/qOzCy/CM=;
        b=WL7rAwndBTJEZH2J/SJtV1VTIt6HZTnNcVKb9hIbzopP9fKpm6aAUYwsXobV8uOx2c
         H7rLpI5RfuNVRkwB9rrEXwKpsXhbs7A4FS/1xRO7xJ74vEowzRabEkrdotibSqeRAl/J
         MVhC2Y7hmBKng8TiCdvoi5x5ZJEq3v3/fDSX2Jvu9+mHEHCqktG7QIfVeVABdoDd/0IS
         7NNMvDjthTJmltDs9gLq5uoC70L1MfXIa4dfIxXhtYToJxFatPAiPZ2/AtbrQRATK9FZ
         LP5FlNeSs46Evy/qZtvwTTcUs3ACkW7/GGcR3WCrGsX534IUSy9hPrMTXEHz5xNDPQ+c
         +Dng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=l4YYQ/GEOmvtTjzStYo8x7IGwbwCnW38Ss/qOzCy/CM=;
        b=lNN7guIRXhswpVnwGoQee0W4lDTz78ajC4NIbYF2jTrYGZ3BVfU9NKgbtKeNCO266o
         Wv7Ma+3InFEOxU46bifja5U+yK8wyP6yLVuy/VHWoTkgdL66Pa8KBvAz5iLqKuSRP3eE
         /DVgD9ljzOlMAcsh/JxOPyJONOGKHzERDWAqzdgP2gaVKZ7wyeLkWlM0rYQqKhZSjhIq
         DEYcT08V0M5PKrwv7lp1y0MsPoHMWY5XTlWLEcvcPN4tF1GVvd+tTJn35neT3D9ko4Vd
         u/o59C+AvppMH5seZe6fYe4oLB1ZfGgyEpK6FPs+NtHRYkZLGCfI16kM6GzRONCeRAj6
         o+5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0cm7YJCZ+VLRUFqCMsEumsv3A8Cu5LaqrqIsLCJfeM98IihDZw
	tb+LWbKul9xKIP1EF8RKwhc=
X-Google-Smtp-Source: AMsMyM6LrBirCgCYtgvWnT7N8Dsvl/BSykEuxobEw7ML25nD9Dzvs9mQTTpIuvplE2OrupNSId+DGg==
X-Received: by 2002:a05:6512:798:b0:497:aa2b:8b10 with SMTP id x24-20020a056512079800b00497aa2b8b10mr3581571lfr.636.1666201069030;
        Wed, 19 Oct 2022 10:37:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f5a:0:b0:48b:2227:7787 with SMTP id 26-20020ac25f5a000000b0048b22277787ls4340775lfz.3.-pod-prod-gmail;
 Wed, 19 Oct 2022 10:37:47 -0700 (PDT)
X-Received: by 2002:ac2:5b12:0:b0:4a3:5a0b:4985 with SMTP id v18-20020ac25b12000000b004a35a0b4985mr3561262lfn.233.1666201067844;
        Wed, 19 Oct 2022 10:37:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666201067; cv=none;
        d=google.com; s=arc-20160816;
        b=IvoNYtro3zGz37pU4YwVDYWW9NodxgoB8fxvrNJ21k02DWNoqyd74GYw/875NqiWty
         lC9dQ8DB437VXERM9b9WEjLf60IFZV3792eyPQUjO8qty5L9wNxS6atYxWPqB3+xrIBW
         fTd3Q44jSZUISlk26zYBCSBMc4HlJTJG8R4frsNF2ZFp925Nqdpw0Q+GokdJA76+Pj4G
         qgme18HbaRw3ESYuz/oMwWMUUfri8yUfP6YbZ/fuAi4jCCQfeChwQBdfYD9GUUh6/Wf1
         5vYVK7z+uCOyMCIIX9+y8gtuDHy5rK5xIqDnLofS6diMiLgyaOOBXHNOMRJHw5tjI+5/
         zCkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=alUQBLEPM/4ut+DBUtv9Ivb5l8ej5D57TPiVHx/bcBI=;
        b=KgGrCRfgOmNOfp1BfwpNmGAyQ+Hm6Mj4wclZpj9N2kIfBhjNw9y0BnZT6+P7sraM0W
         kxjhZE2Z4fIKAI90y8CiADWSiU0ED2okFp4h82Aro+DtgQHpnfSLLpbgy9cbCStccGUi
         e+2UhRX9iAbk3Rpk/gwNcIjPNimf8nZt6kWupQ2yr+e47RJiOMOT+fMkRVv2GLTj39yQ
         me7gZ0BlTed5r4UKQjl5CLwR52T4OJ7vMk6JWiM74i8KRUCYcQ00mqkhqTI6rTKZsNQ8
         SW2awlbXd8X82fKGBuhu0riIVmaUZzybKznyifgIF5WvXXegeqra44c9LCffM65UKA54
         dphw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=MEjHkmlZ;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id s5-20020a056512314500b004a469aa668dsi308922lfi.8.2022.10.19.10.37.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 10:37:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id d6so29330332lfs.10
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 10:37:47 -0700 (PDT)
X-Received: by 2002:a05:6512:758:b0:4a2:be27:c8f0 with SMTP id
 c24-20020a056512075800b004a2be27c8f0mr3154375lfs.681.1666201067381; Wed, 19
 Oct 2022 10:37:47 -0700 (PDT)
MIME-Version: 1.0
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
In-Reply-To: <20221019173620.10167-1-youling257@gmail.com>
From: youling 257 <youling257@gmail.com>
Date: Thu, 20 Oct 2022 01:37:35 +0800
Message-ID: <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
Subject: Fwd: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"\"Michael S. Tsirkin\"" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: multipart/alternative; boundary="000000000000bee9ab05eb66aa1c"
X-Original-Sender: YOULING257@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=MEjHkmlZ;       spf=pass
 (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=youling257@gmail.com;       dmarc=pass
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

--000000000000bee9ab05eb66aa1c
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

---------- Forwarded message ---------
=E5=8F=91=E4=BB=B6=E4=BA=BA=EF=BC=9A youling257 <youling257@gmail.com>
Date: 2022=E5=B9=B410=E6=9C=8820=E6=97=A5=E5=91=A8=E5=9B=9B =E4=B8=8A=E5=8D=
=881:36
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: <glider@google.com>
Cc: <youling257@gmail.com>


i using linux kernel 6.1rc1 on android, i use gcc12 build kernel 6.1 for
android, CONFIG_KMSAN is not set.
"instrumented.h: add KMSAN support" cause android bluetooth high CPU usage.
git bisect linux kernel 6.1rc1, "instrumented.h: add KMSAN support" is a
bad commit for my android.

this is my kernel 6.1,  revert include/linux/instrumented.h fix high cpu
usage problem.
https://github.com/youling257/android-mainline/commits/6.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAOzgRda_CToTVicwxx86E7YcuhDTcayJR%3DiQtWQ3jECLLhHzcg%40mail.gmai=
l.com.

--000000000000bee9ab05eb66aa1c
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"><div><br><br><div class=3D"gmail_quote"><div dir=3D"ltr" =
class=3D"gmail_attr">---------- Forwarded message ---------<br>=E5=8F=91=E4=
=BB=B6=E4=BA=BA=EF=BC=9A <strong class=3D"gmail_sendername" dir=3D"auto">yo=
uling257</strong> <span dir=3D"auto">&lt;<a href=3D"mailto:youling257@gmail=
.com">youling257@gmail.com</a>&gt;</span><br>Date: 2022=E5=B9=B410=E6=9C=88=
20=E6=97=A5=E5=91=A8=E5=9B=9B =E4=B8=8A=E5=8D=881:36<br>Subject: Re: [PATCH=
 v7 18/43] instrumented.h: add KMSAN support<br>To:  &lt;<a href=3D"mailto:=
glider@google.com">glider@google.com</a>&gt;<br>Cc:  &lt;<a href=3D"mailto:=
youling257@gmail.com">youling257@gmail.com</a>&gt;<br></div><br><br>i using=
 linux kernel 6.1rc1 on android, i use gcc12 build kernel 6.1 for android, =
CONFIG_KMSAN is not set.<br>
&quot;instrumented.h: add KMSAN support&quot; cause android bluetooth high =
CPU usage.<br>
git bisect linux kernel 6.1rc1, &quot;instrumented.h: add KMSAN support&quo=
t; is a bad commit for my android.<br>
<br>
this is my kernel 6.1,=C2=A0 revert include/linux/instrumented.h fix high c=
pu usage problem.<br>
<a href=3D"https://github.com/youling257/android-mainline/commits/6.1" rel=
=3D"noreferrer noreferrer" target=3D"_blank">https://github.com/youling257/=
android-mainline/commits/6.1</a><br>
</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAOzgRda_CToTVicwxx86E7YcuhDTcayJR%3DiQtWQ3jECLLhHzcg%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAOzgRda_CToTVicwxx86E7YcuhDTcayJR%3DiQtWQ3jECLLh=
Hzcg%40mail.gmail.com</a>.<br />

--000000000000bee9ab05eb66aa1c--
