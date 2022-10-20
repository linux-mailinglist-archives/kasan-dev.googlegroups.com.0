Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJ5AY2NAMGQEGE76U6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B443D606807
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 20:15:05 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id x21-20020a5d9455000000b006bc1172e639sf202042ior.18
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 11:15:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666289704; cv=pass;
        d=google.com; s=arc-20160816;
        b=PfXb4GhNvbBZChO79ke7PYXHdjyfamOTyz0h5Jq5yQMeGcEaoPBsQNptgUeiDlEL9O
         rKZLwwcLhUK/+UcbBK7zAJ6+rbz+lAp5TyAgkNfSG1yTRXqB7AwpOy47tEQZG1zncROg
         SR+Hic4sG6JBKqhnWN+Saf9BwLU93us6045kL0BJolh0ywZrijLtVT6y/LMLmJA0azv4
         hpsBCyFTVHF1IEosJff9SRNF1O1Y3vnj/jquevNc0m8i9iIc3vXkEFfjgb1DqqN3vold
         l8eBcVHzskUmJIP5/B174DbW9E8qMTsiAtJcpESSbMBdE2TSlBcsvIxPsFYRhLhl+f2i
         NLPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KEb6rj1m0e8JuCfFOoO4WLxYJnFQDgEhR6sAoGnTTLQ=;
        b=VOwXxOcnPtN7h/9qARdgeDXQdOXx5BcFGjhrGF9mMCivzGcLf10uHYDmyRoT7zbsG0
         p+5whK1GXQCNMFRbz+bF24/NSqAtfjxPMHg6rRhYvT9Cc3an1Y1ZY4PsZujs3ulf3izs
         Ouk8VTpzxNMSxp6TyRWxATWXrgsJmXfsTiWhqYr6S7+dxI3kQUmuE5bqb7H0LbUz/QEu
         hBu+r28Qw0fsVAvcenL4S5xiNNnCtStkA0Hdq6n1BfHQk2FDKLjV8+lyWKl3Dfj+vB2B
         K/25nHRURMLQzra8yjVSeiGZePVRAa1dcoC04ddHj7vBmHV8mQsWE78PygsLOsmVXUqk
         lIag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=a2MCT5vl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KEb6rj1m0e8JuCfFOoO4WLxYJnFQDgEhR6sAoGnTTLQ=;
        b=Aov9UMQtiiHTkvIJQbItcUKFadIVfrzDFj/tzkAmssP6tbissROd0I6ChPSavZQ4uy
         n69BhjK+rHxBQ9qLk+qUEubPQbyI7UGXJJ3c0Khtzf8FwRCxppWdVPjM9CASdh4wQSZh
         J0Z6XogKwg5dElNAFDrUCPkwNy0GgC4P+vJ3GUu1nGDpow0c0yA4npEAtzZRaZvygJpx
         Oby7ra5fOuFQokQBCf+p2KRrmVEZYM11QZw+VzHcbHcM05y+9w30svB+DEuNKrABfFQs
         dLnRxo7GfLExi+lYg6I+8coSnp8tx1bXeZm2Jj/BJto3v3k5NvONCFVpbPbNmFbWt88c
         Kv6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=KEb6rj1m0e8JuCfFOoO4WLxYJnFQDgEhR6sAoGnTTLQ=;
        b=vKs3neoAwnk8FhlDPSvfROYZPr0vGgUVH0mY8tNVT1wlOr1VLvSsmMfysqumXiis2R
         NTFqWfyRrf5I79RCbNadBQgwR0wiKYLUMCumJKUWR0ZcOozlR3fpISFwqkAqjerUm4l3
         YYDjxs5/ULWXVj7nTlP1M0FJJulExB1gFu3sJr429uSGAONDoXEMwUgkTouiqH2ASe8e
         D4zS8eojOzC7x0l3ajheBNO+cqnwgLVCyLWKhO9kwYxHS23FEaDo+LDGiNY5cAQgBjt7
         NeG/vv+CTyq567ZiDPSkTkKJ4sI5CvXXk1OobFzGSKTnJzWfxJZW8Zj0uLPSMApmuim6
         AWfA==
X-Gm-Message-State: ACrzQf1uVrP/KzReQXlsL935tA6VeFpuIepJ3XWBF6AKstkP3oLTUorl
	cWcEYPADybsIcfqXuCC65JE=
X-Google-Smtp-Source: AMsMyM7+q4uCKnTf+yX3w1UwZS3W6YuGEFPehg42ybtyvlGL1e0NMMPF2rBSi++e4W+433P8PGOA5g==
X-Received: by 2002:a05:6e02:1988:b0:2fc:907b:d1b4 with SMTP id g8-20020a056e02198800b002fc907bd1b4mr10565606ilf.155.1666289703875;
        Thu, 20 Oct 2022 11:15:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:8541:0:b0:35e:234b:8f1d with SMTP id g59-20020a028541000000b0035e234b8f1dls96262jai.9.-pod-prod-gmail;
 Thu, 20 Oct 2022 11:15:03 -0700 (PDT)
X-Received: by 2002:a05:6638:1b0f:b0:363:b6a1:bd23 with SMTP id cb15-20020a0566381b0f00b00363b6a1bd23mr11425873jab.152.1666289703390;
        Thu, 20 Oct 2022 11:15:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666289703; cv=none;
        d=google.com; s=arc-20160816;
        b=xlw+G7atIEfBA/8g7VmVhzLhsBCrS1x+STdheBpztUYAAQixs5yLmor4lvkea0cXKr
         PF8+hxRpVbLl2jdlB2iHamIEEIkg9ZlrcWl843FwviN9SmhHpwaTvjSoBJvO68q/H149
         5ykh3VDFc2ervfmlKv/fQhotSD1IrQB7v7O5wNEaC9qr/3giU7zfO9cZ7V31AJCNh/l8
         HIse1RqbJJDIEm7xyIHM7CkkiMoPQ+hGdYxFi/FSudTN1YtX2QdL1T+P8pUUV4VK0Hqz
         QBsFejPjL5HdXjGra/B3bhV/eyIBsBXVu3FEnP9kDJt+mCpHlNTp1obmujaGABfGyHCC
         38LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DeaJx4U9U/HouZlNtQYOnX4gYJD8uJB8N7NUzo4qBYg=;
        b=rDCD2p7veYalQqMep4hZz4DNlCEVSaBbOeCSpXr8sCJxVrCl0hNVR8Kjw3RMaw3Lga
         SvmXQSqZ4OlDJ4amLTUbOfnoFwGePbAhVrmCfniKFt6sJBbzhbI8wJs2EK5YDjlPdKzi
         OMyo0G7/zpjG0Y1W7cFGNzSbJXfgzvHsxJaChhB1hGduUHFCdS4P9lVJS4vTUB+QYD3m
         NTSvutfXA8YRIdCPIiI0R6P4/woCnOrTkExIs++rA/9wv5uxV+xPdEgcsBMSExcq90QO
         +ghs/e5E2Mvq1UdyZljtRelBvawRQ1f/osC9FgW+M2W74ehqk5QioJe5aTGy2RQ1QrhX
         0nkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=a2MCT5vl;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id t16-20020a02c490000000b00365c4aa7d03si567144jam.3.2022.10.20.11.15.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Oct 2022 11:15:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id j130so526886ybj.9
        for <kasan-dev@googlegroups.com>; Thu, 20 Oct 2022 11:15:03 -0700 (PDT)
X-Received: by 2002:a05:6902:102b:b0:6bf:f3c2:dc4c with SMTP id
 x11-20020a056902102b00b006bff3c2dc4cmr13097919ybt.376.1666289702621; Thu, 20
 Oct 2022 11:15:02 -0700 (PDT)
MIME-Version: 1.0
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com>
 <Y1BXQlu+JOoJi6Yk@elver.google.com> <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
 <Y1Bt+Ia93mVV/lT3@elver.google.com>
In-Reply-To: <Y1Bt+Ia93mVV/lT3@elver.google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Oct 2022 11:14:26 -0700
Message-ID: <CAG_fn=WLRN=C1rKrpq4=d=AO9dBaGxoa6YsG7+KrqAck5Bty0Q@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: Marco Elver <elver@google.com>
Cc: youling 257 <youling257@gmail.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Biggers <ebiggers@kernel.org>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: multipart/alternative; boundary="000000000000d1ca6505eb7b4d0d"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=a2MCT5vl;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as
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

--000000000000d1ca6505eb7b4d0d
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, Oct 19, 2022 at 2:37 PM 'Marco Elver' via kasan-dev <
kasan-dev@googlegroups.com> wrote:

> On Thu, Oct 20, 2022 at 04:07AM +0800, youling 257 wrote:
> > That is i did,i already test, remove "u64 __tmp=E2=80=A6kmsan_unpoison_=
memory",
> no help.
> > i only remove kmsan_copy_to_user, fix my issue.
>
> Ok - does only the below work (without the reverts)?
>
> diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
> index c4cae333deec..eb05caa8f523 100644
> --- a/include/linux/kmsan-checks.h
> +++ b/include/linux/kmsan-checks.h
> @@ -73,8 +73,8 @@ static inline void kmsan_unpoison_memory(const void
> *address, size_t size)
>  static inline void kmsan_check_memory(const void *address, size_t size)
>  {
>  }
> -static inline void kmsan_copy_to_user(void __user *to, const void *from,
> -                                     size_t to_copy, size_t left)
> +static __always_inline void kmsan_copy_to_user(void __user *to, const
> void *from,
> +                                              size_t to_copy, size_t lef=
t)
>  {
>  }
>
>
> ... because when you say only removing kmsan_copy_to_user() (from
> instrument_put_user()) works, it really doesn't make any sense. The only
> explanation would be if the compiler inlining is broken.
>
>
If what Marco suggests does not help, could you post the output of `nm -S
vmlinux` with and without your revert so that we can see which functions
were affected by the change?

Unfortunately the top results are of no help, do you have the `perf` tool
available in your system?


> --
> You received this message because you are subscribed to the Google Groups
> "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an
> email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/Y1Bt%2BIa93mVV/lT3%40elver.go=
ogle.com
> .
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWLRN%3DC1rKrpq4%3Dd%3DAO9dBaGxoa6YsG7%2BKrqAck5Bty0Q%40m=
ail.gmail.com.

--000000000000d1ca6505eb7b4d0d
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div dir=3D"ltr"><br></div><br><div class=3D"gmail_quote">=
<div dir=3D"ltr" class=3D"gmail_attr">On Wed, Oct 19, 2022 at 2:37 PM &#39;=
Marco Elver&#39; via kasan-dev &lt;<a href=3D"mailto:kasan-dev@googlegroups=
.com">kasan-dev@googlegroups.com</a>&gt; wrote:<br></div><blockquote class=
=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rg=
b(204,204,204);padding-left:1ex">On Thu, Oct 20, 2022 at 04:07AM +0800, you=
ling 257 wrote:<br>
&gt; That is i did,i already test, remove &quot;u64 __tmp=E2=80=A6kmsan_unp=
oison_memory&quot;, no help.<br>
&gt; i only remove kmsan_copy_to_user, fix my issue.<br>
<br>
Ok - does only the below work (without the reverts)?<br>
<br>
diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h<br=
>
index c4cae333deec..eb05caa8f523 100644<br>
--- a/include/linux/kmsan-checks.h<br>
+++ b/include/linux/kmsan-checks.h<br>
@@ -73,8 +73,8 @@ static inline void kmsan_unpoison_memory(const void *addr=
ess, size_t size)<br>
=C2=A0static inline void kmsan_check_memory(const void *address, size_t siz=
e)<br>
=C2=A0{<br>
=C2=A0}<br>
-static inline void kmsan_copy_to_user(void __user *to, const void *from,<b=
r>
-=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0size_t to_copy, =
size_t left)<br>
+static __always_inline void kmsan_copy_to_user(void __user *to, const void=
 *from,<br>
+=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 size_t to_copy, size_t left)<br>
=C2=A0{<br>
=C2=A0}<br>
<br>
<br>
... because when you say only removing kmsan_copy_to_user() (from<br>
instrument_put_user()) works, it really doesn&#39;t make any sense. The onl=
y<br>
explanation would be if the compiler inlining is broken.<br>
<br></blockquote><div><br></div><div>If what Marco suggests does not help, =
could you post the output of `nm -S vmlinux` with and without your revert s=
o that we can see which functions were affected by the change?</div><div><b=
r></div><div>Unfortunately the top results are of no help, do you have the =
`perf` tool available in your system?=C2=A0</div><div>=C2=A0</div><blockquo=
te class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px =
solid rgb(204,204,204);padding-left:1ex">
-- <br>
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br>
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googlegroups.com" target=
=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/Y1Bt%2BIa93mVV/lT3%40elver.google.com" rel=3D"noreferr=
er" target=3D"_blank">https://groups.google.com/d/msgid/kasan-dev/Y1Bt%2BIa=
93mVV/lT3%40elver.google.com</a>.<br>
</blockquote></div><br clear=3D"all"><div><br></div>-- <br><div dir=3D"ltr"=
 class=3D"gmail_signature"><div dir=3D"ltr">Alexander Potapenko<br>Software=
 Engineer<br><br>Google Germany GmbH<br>Erika-Mann-Stra=C3=9Fe, 33<br>80636=
 M=C3=BCnchen<br><br>Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebasti=
an<br>Registergericht und -nummer: Hamburg, HRB 86891<br>Sitz der Gesellsch=
aft: Hamburg<br></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DWLRN%3DC1rKrpq4%3Dd%3DAO9dBaGxoa6YsG7%2BKrqAc=
k5Bty0Q%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://gr=
oups.google.com/d/msgid/kasan-dev/CAG_fn%3DWLRN%3DC1rKrpq4%3Dd%3DAO9dBaGxoa=
6YsG7%2BKrqAck5Bty0Q%40mail.gmail.com</a>.<br />

--000000000000d1ca6505eb7b4d0d--
