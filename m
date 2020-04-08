Return-Path: <kasan-dev+bncBD7OB4EO4UNRBM4PW72AKGQEZ3BDVBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id EC0DC1A2243
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Apr 2020 14:46:44 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id c123sf5584641oig.19
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Apr 2020 05:46:44 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dOwCTgeU1EbZ/hsM2Qd3oLLHkwUS96nGH2+9pOjwKEw=;
        b=g83SEFt0Tq2qewQid9Y+uCQp6ZLHv07hQ7PXHVHO8b4xOHFDUaHXFUdfUx0CSeUzTo
         pKlwLlmA4hO5WEcP6jSeb4S39vT+HRl4hI2v5ItJl2SjDZPxHY0vfMeo273vPQpIhEwU
         H6CDGZ/VmqCioVJmPAJvdGXPU236FoXvXWpmA1HQpQB60NLp0rYN/2x/6WyGpRJqRaGL
         N64WoI1aL29zUmV6B8oXe6vC4hLxJTBHfsRY3uJSofqtdTG7S3YvK75Ro3TpRpRAt4L8
         Zk64Flzuirq0ypRC2f+0SuWRWS7MuszDqZz3QZ7WH7Ss9ouR2gF5Jr2oLL9FGfTqp1WF
         lGqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dOwCTgeU1EbZ/hsM2Qd3oLLHkwUS96nGH2+9pOjwKEw=;
        b=P6Y1rkaAhhwxJ6jgMSm6/X8YL7KCb5CmSGmUZrwPxZxZDnYBAW2Eem85XkizGICocM
         /QTZazbBo/oVhIwzEFtM/otjQfo3Wynm5IXvJDs8NcH/fStk0+ymqvsnFRynf5QtWVQa
         AJJ7/yjpSliU2qhoroNtJKozk75muCJskcR2IM6VPTjiohQBTAe7NcdVSa39410x/xsx
         SE2x6z8+MiuILhGnWSglJHElIR/LJxJpLX6bEDmjoADEQak+SMH1EqHLFQ5tgX40FQ6w
         FO1Q8nic90uC6sNszTTWxtmfE8qfyWRNHuw8xzlSdZW2sUQATV9ZFYQYL6fizAvmZPvX
         U+VA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dOwCTgeU1EbZ/hsM2Qd3oLLHkwUS96nGH2+9pOjwKEw=;
        b=BPo84EkFt0/d4DANrCrzaX98CcSFZgm1owAYfq66UEZtPgaj/gTvh6dFGQYMzn7itu
         5NTkVZTm6NSHNSDuVmSIwbs4TBFKiOcuxAeFK25wZX7tLhCywnEsh/qvOuWYXPTdm8Qu
         YTxc0wtUN/jUPJJN888szgzF1nyfNUy8sbKpL/LwIdObN02krzjZ/Lg5xF18mR6TH/f7
         fIHpSmNvuNBHeg7IDtLibX6qQ9q4JLbonToPhn42ttuRmecNmAiot3Wep/3JeN+z1OtK
         ya4vK/+ZsLihk2WMCeWesLoPeBRp5tZsHsuXoeAqGEHB9Mdqi1WER1xKB7k2x94jVPeD
         MzLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYQqoVCwdSBmYZKsasUdgZu0qrIxhqRkxDTq5wISW3vahj9CfUS
	sx0UUv6BKHNNNIw2xPKk2hM=
X-Google-Smtp-Source: APiQypJo2dpEjfucLAPVieh1PSCUL8fuXkgY8MzMhLyUMP6ACX9T94SwTrMSgrm4SvJwjhZ/FAZT4Q==
X-Received: by 2002:a05:6830:200c:: with SMTP id e12mr5651987otp.198.1586350003599;
        Wed, 08 Apr 2020 05:46:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2c44:: with SMTP id o65ls97035ooo.0.gmail; Wed, 08 Apr
 2020 05:46:43 -0700 (PDT)
X-Received: by 2002:a4a:3ec1:: with SMTP id t184mr4349731oot.3.1586350003081;
        Wed, 08 Apr 2020 05:46:43 -0700 (PDT)
Date: Wed, 8 Apr 2020 05:46:42 -0700 (PDT)
From: Johannes Wagner <ickyphuz@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <ba750089-8719-4db8-bea4-6b857c9bc28e@googlegroups.com>
In-Reply-To: <CACT4Y+ZNfHQRP9NJE3LP+8Q9UOutDPs+Oa8wYEA-dhWi-6qU9w@mail.gmail.com>
References: <78d7f888-7960-433f-9807-d703e57002bf@googlegroups.com>
 <CACT4Y+ZvX1Cs1SJppVfLXyV9F4hra=JdBaQCqBTeFX3++f48kQ@mail.gmail.com>
 <CACT4Y+abK5o34h_rks7HMivmVigTG3CM9X93MOt9d7B6dxY_9w@mail.gmail.com>
 <CABDgRhumwQxxpQDmGq6=zf9Xi4DY4tM=_kOdbf=SFvfPYMNYrQ@mail.gmail.com>
 <CACT4Y+aqy0MgJntoKPcjoxnyH3w4n0UW5yxFJX-prm-Zgqn+0g@mail.gmail.com> <fe8bfc10-2d1c-4f47-9f11-df4d3c77a7d7@googlegroups.com>
 <CACT4Y+ZNfHQRP9NJE3LP+8Q9UOutDPs+Oa8wYEA-dhWi-6qU9w@mail.gmail.com>
Subject: Re: [libfuzzer] Linker fails on finding Symbols on (Samsung)
 Android Kernel Build
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_3027_390838739.1586350002705"
X-Original-Sender: ickyphuz@gmail.com
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

------=_Part_3027_390838739.1586350002705
Content-Type: multipart/alternative; 
	boundary="----=_Part_3028_53639536.1586350002706"

------=_Part_3028_53639536.1586350002706
Content-Type: text/plain; charset="UTF-8"

yes, that was also my fist thought because the other functions are found by 
the linker after the backporting.

 I was thinking maybe the macro expansion fails on the double zero and 
expanded it by hand for this function ...but did not work

//mm/kasan/kasan.c
void __asan_set_shadow_00(const void *addr, size_t size)
{
        __memset((void *)addr, 0x00, size);
}
EXPORT_SYMBOL(__asan_set_shadow_00);


// mm/kasan/kasan.h has also the declaration
void __asan_set_shadow_00(const void *addr, size_t size);



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ba750089-8719-4db8-bea4-6b857c9bc28e%40googlegroups.com.

------=_Part_3028_53639536.1586350002706
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>yes, that was also my fist thought because the other =
functions are found by the linker after the backporting.<br></div><div><br>=
</div><div>=C2=A0I was thinking maybe the macro expansion fails on the doub=
le zero and expanded it by hand for this function ...but did not work<br></=
div><div><br></div><div><div style=3D"background-color: rgb(250, 250, 250);=
 border-color: rgb(187, 187, 187); border-style: solid; border-width: 1px; =
overflow-wrap: break-word;" class=3D"prettyprint"><code class=3D"prettyprin=
t"><div class=3D"subprettyprint"><span style=3D"color: #800;" class=3D"styl=
ed-by-prettify">//mm/kasan/kasan.c</span><span style=3D"color: #000;" class=
=3D"styled-by-prettify"><br></span><span style=3D"color: #008;" class=3D"st=
yled-by-prettify">void</span><span style=3D"color: #000;" class=3D"styled-b=
y-prettify"> __asan_set_shadow_00</span><span style=3D"color: #660;" class=
=3D"styled-by-prettify">(</span><span style=3D"color: #008;" class=3D"style=
d-by-prettify">const</span><span style=3D"color: #000;" class=3D"styled-by-=
prettify"> </span><span style=3D"color: #008;" class=3D"styled-by-prettify"=
>void</span><span style=3D"color: #000;" class=3D"styled-by-prettify"> </sp=
an><span style=3D"color: #660;" class=3D"styled-by-prettify">*</span><span =
style=3D"color: #000;" class=3D"styled-by-prettify">addr</span><span style=
=3D"color: #660;" class=3D"styled-by-prettify">,</span><span style=3D"color=
: #000;" class=3D"styled-by-prettify"> size_t size</span><span style=3D"col=
or: #660;" class=3D"styled-by-prettify">)</span><span style=3D"color: #000;=
" class=3D"styled-by-prettify"><br></span><span style=3D"color: #660;" clas=
s=3D"styled-by-prettify">{</span><span style=3D"color: #000;" class=3D"styl=
ed-by-prettify"><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 __memset</span><span style=
=3D"color: #660;" class=3D"styled-by-prettify">((</span><span style=3D"colo=
r: #008;" class=3D"styled-by-prettify">void</span><span style=3D"color: #00=
0;" class=3D"styled-by-prettify"> </span><span style=3D"color: #660;" class=
=3D"styled-by-prettify">*)</span><span style=3D"color: #000;" class=3D"styl=
ed-by-prettify">addr</span><span style=3D"color: #660;" class=3D"styled-by-=
prettify">,</span><span style=3D"color: #000;" class=3D"styled-by-prettify"=
> </span><span style=3D"color: #066;" class=3D"styled-by-prettify">0x00</sp=
an><span style=3D"color: #660;" class=3D"styled-by-prettify">,</span><span =
style=3D"color: #000;" class=3D"styled-by-prettify"> size</span><span style=
=3D"color: #660;" class=3D"styled-by-prettify">);</span><span style=3D"colo=
r: #000;" class=3D"styled-by-prettify"><br></span><span style=3D"color: #66=
0;" class=3D"styled-by-prettify">}</span><span style=3D"color: #000;" class=
=3D"styled-by-prettify"><br>EXPORT_SYMBOL</span><span style=3D"color: #660;=
" class=3D"styled-by-prettify">(</span><span style=3D"color: #000;" class=
=3D"styled-by-prettify">__asan_set_shadow_00</span><span style=3D"color: #6=
60;" class=3D"styled-by-prettify">);</span></div></code></div><br></div><di=
v><br></div><div><div style=3D"background-color: rgb(250, 250, 250); border=
-color: rgb(187, 187, 187); border-style: solid; border-width: 1px; overflo=
w-wrap: break-word;" class=3D"prettyprint"><code class=3D"prettyprint"><div=
 class=3D"subprettyprint"><span style=3D"color: #800;" class=3D"styled-by-p=
rettify">// mm/kasan/kasan.h has also the declaration</span><span style=3D"=
color: #000;" class=3D"styled-by-prettify"><br></span><span style=3D"color:=
 #008;" class=3D"styled-by-prettify">void</span><span style=3D"color: #000;=
" class=3D"styled-by-prettify"> __asan_set_shadow_00</span><span style=3D"c=
olor: #660;" class=3D"styled-by-prettify">(</span><span style=3D"color: #00=
8;" class=3D"styled-by-prettify">const</span><span style=3D"color: #000;" c=
lass=3D"styled-by-prettify"> </span><span style=3D"color: #008;" class=3D"s=
tyled-by-prettify">void</span><span style=3D"color: #000;" class=3D"styled-=
by-prettify"> </span><span style=3D"color: #660;" class=3D"styled-by-pretti=
fy">*</span><span style=3D"color: #000;" class=3D"styled-by-prettify">addr<=
/span><span style=3D"color: #660;" class=3D"styled-by-prettify">,</span><sp=
an style=3D"color: #000;" class=3D"styled-by-prettify"> size_t size</span><=
span style=3D"color: #660;" class=3D"styled-by-prettify">);</span><span sty=
le=3D"color: #000;" class=3D"styled-by-prettify"><br><br></span></div></cod=
e></div><br><br></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/ba750089-8719-4db8-bea4-6b857c9bc28e%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/ba750089-8719-4db8-bea4-6b857c9bc28e%40googlegroups.com</a>.<br =
/>

------=_Part_3028_53639536.1586350002706--

------=_Part_3027_390838739.1586350002705--
