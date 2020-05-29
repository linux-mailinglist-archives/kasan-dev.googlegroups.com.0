Return-Path: <kasan-dev+bncBCFLDU5RYAIRB565YX3AKGQECGTERJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F9F71E88D3
	for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 22:22:16 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id y23sf202960lfy.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 May 2020 13:22:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590783735; cv=pass;
        d=google.com; s=arc-20160816;
        b=hT9YIVs7lfZzgt85gn6pCsvZuwPQQros2RcxuyLPhQKsg5v3BWc32m6EzVBmKMadgw
         JthxcsZBietvQfhVM8iTckBYTTcM1wpfQEQzDQBsP0JMgVLjvHB7N5N2kwXPxIWuj3sJ
         7i3FZPa6UXysf6zWX5Q8Zmlr2C/MJox8l8pVSRuWKwqpZIrKUV7xMRlSiSCD+WcdfrLM
         n5VcNBa+vwmxpwk3VpaKudHr4GaI8wmw6YgoyXCqov6K8bQm1Iyl9/Cey/0xV/D1PvB2
         Z6XPStKflJEo6jMlI09rLRb4Ld1YX3MfXf65ad1yHCv2kALpzmiG28b04tsato36u+D4
         h/Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=iYIBWSUIR9qJBjlBZAIfT6ttLgE17Z007gNpH8DtwKM=;
        b=p80Z3eLFmn4ao9i73xVyCg945LW49zlc2AFj5EMj05Xnd/xtt4SOjchR2zMCS60pHQ
         U4MNP/irQvUhjVRx8hgdE6kXf4acADjNulMImnfhovqb3X51lsNZcYSB1XiGZuru+PMQ
         cHziJyZ4/b+ziE/0hnry5d4v/0hYOa/lcp7LNFXOQACV/9ka6Ccb5B7CRXGbOKtuhJ1j
         xgN7Axz9nzpuPXqCog2WmJrD+59XMCnQjf8KTR3VE6p4tbKY3FkWTKYnQI7JJh98n0mn
         aFnDH2h3hXFHQeetOSQQdNKQ+f3Rzon6Jj+rS/FYawljlrsxOeAOq/eEKO08RCt6qQnI
         zV6A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nUFa1pAN;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYIBWSUIR9qJBjlBZAIfT6ttLgE17Z007gNpH8DtwKM=;
        b=XYf0DyndbnQLAEJqVaDP3fYSHDLUI4uA4tueUMsj8uDiSsdqcR/0QGvc8Pq+sHAfiS
         tuDhmFkXTnQIuGc+2cYgqj1Fp9Jj6cKb8DQzzrfRP0PTxGJwOK84VUp1cfoyUGUWYwf8
         ugEu3Dw5iT34Cq84UH4roJCOSme1jW5QwuOMqqi/uJCkn+0rgSdVwx7KKA9P1HKJRu/n
         J2K1ZC7MqP4swMQMeWGATUrl4FPmoqs/3i0Imcb1Lj6mwcl1gJ2x2Zp6fPnHDQe9JWxb
         k5wgeUoq32GQ3PW0sCY/XFOJBTdd2ZdIqhABMTU4w9WD4I/x2Q4lcFFUaTTwFqeMN+RY
         /HNw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYIBWSUIR9qJBjlBZAIfT6ttLgE17Z007gNpH8DtwKM=;
        b=OLSu7nSDhFd+kV3JWOTStGb08QmgsdMo05rMsV9D/XDtls5FXWu8meYecsDwEgOJmR
         13m2Akv83cSw21+fHxOQPB+ok+lyKVCLu6TP33FfxcWpkFHSQ+le3loanc1h5lSCfhFp
         a7u7P/1K0sFKy8xebQcwp5H9LTwsC7E54ynDqTonfCIY264Aq+exgcA1YxCJhHz6nWQ1
         y2ruOf0yyBp53p9YmCv6Bv8sRrQsAvd0BbeFKoqPcLpI6zlxnfFmTygTSelLHc8HrtHd
         8W3Gm3tZIlOPdKfz1wt0BQufPnqi5hjt/Mt1M3Ol6vLc/ndXgGsn5Hv1B1MJtZHxrM4H
         i3uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYIBWSUIR9qJBjlBZAIfT6ttLgE17Z007gNpH8DtwKM=;
        b=JaSMCl2Ks71udJw0XnKMz6v7CgyxIb31Ek2KWCaBtVT9gTBdhJClk9xMdgqW1dbxTs
         qb1Y8/8k3O76exzPsTQdRu/qUmuuFNoX+eFkN959CdAmO9XK2GHMRCt1e+hyj4mNLWz3
         C8JFi4b0aephBkIWqq5rw0Ydieof2L0P/1mHeNIrIjETBaexJxeiCyeHEFTq6clqlyLD
         f4Wpc1jXH6Gw+MIX3Cnt5HSAJddz9BkJiwHNyW2djgqVRP1+Xq+es3VyswRhPoJ7EEZl
         rGs2yeZqoCA1Z04yu5E5jv3LpSNGa9Rpwcg4j4YkDbWTwtykCeHYRxn43IH6Hj9xTswV
         TeIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314OdP0JMW2jaOY2JauDqubzWnyAlWsEM4DJGXXztEf2odyoo0x
	8siFS3u4fW7VgY7Fwn18Joo=
X-Google-Smtp-Source: ABdhPJyssGivfaMQqjH5wWzZawQMGLWfhitIaZS/JvduL3IXxLT0I9KUeXd3VGPxgMeevVHRzKVvPw==
X-Received: by 2002:a2e:9c45:: with SMTP id t5mr5444971ljj.344.1590783735611;
        Fri, 29 May 2020 13:22:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:6817:: with SMTP id c23ls440580lja.0.gmail; Fri, 29 May
 2020 13:22:14 -0700 (PDT)
X-Received: by 2002:a2e:9910:: with SMTP id v16mr5051454lji.213.1590783734850;
        Fri, 29 May 2020 13:22:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590783734; cv=none;
        d=google.com; s=arc-20160816;
        b=R87X3XUYkJPnsy3sbOWXGHCU38OPm9gC8bSpYGxn9ourRg/0vSGiNT55/BTq18jWe9
         SfXrporWvtzCy2LItA7i24fEmLBiLwmOb2srgS4CQL8y1H1QNaLwaoTQWDve2a0yvfPa
         AEzgX6oWVH2GdSi2+gCWiZRcSg4ZeZ4JYQo4mklJxGGjA0R3hDKiMECvTg3lldE2ZRxj
         n0kvIqN77crv+zFNxtFqCgxjuMBBqsztuuIf7CY0FD4QRi/D+ejky/MTCl1+WS73VAwq
         H5jGsg7Eg9q8VcuzWfZVFfcgG7wTD9sGbfgejc3NXIucwG3Jbervs62GkFzk9D8KHYpc
         QhIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+buKSvF0eFyQbmsng6ub/bCyG/LlDXDWzpAoDc+j2jY=;
        b=x1owplbGArKBmZ2OIlgHFNeOZF+4rQtmrQE/RkJ9Dw1OQ35rW3xMZagvoLxHzi4ay1
         F0tur7jtTy51cdHKKJAMLRNKzGOkoKC9r+LbAzMxuo3aRH/E/APzzOLJcSh4V7SokIHk
         nbjle5o1yMzb/cj3sGXemblcOYT20ZfJuXD63wE229qJtnuV9me/MYN4zKO1KiEYCUFU
         EAMBZt2ebNbplnPBKqtJlwlPp6wMO4YUPkeLL9qMjcRF21W6qmRHyew89uHWO7nVGeDI
         JqDxnZRWH0TSj7gzM/pZMRx8fWQthhJb3FswoHYlv6sRQV2DAwaKS/xVpIQr17uCqKtE
         uLZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nUFa1pAN;
       spf=pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id c144si441308lfg.5.2020.05.29.13.22.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 May 2020 13:22:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of venkat.rajuece@gmail.com designates 2a00:1450:4864:20::241 as permitted sender) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id b6so847646ljj.1
        for <kasan-dev@googlegroups.com>; Fri, 29 May 2020 13:22:14 -0700 (PDT)
X-Received: by 2002:a2e:97c3:: with SMTP id m3mr4604944ljj.23.1590783734474;
 Fri, 29 May 2020 13:22:14 -0700 (PDT)
MIME-Version: 1.0
References: <CA+dZkamtaXi8yr=khO+E9SKe9QBR-Z0e0kdH4DzhQdzo8o-+Eg@mail.gmail.com>
 <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
In-Reply-To: <CACT4Y+YS5b2PokFVvw69Mfo-jjE13jGAqYmtEJQa7tVHm=CjgQ@mail.gmail.com>
From: Raju Sana <venkat.rajuece@gmail.com>
Date: Fri, 29 May 2020 13:22:03 -0700
Message-ID: <CA+dZkanWfzQ-dYMvqW5BG_bsxk-km-B-1r+vv7HjD3-cDOfxrA@mail.gmail.com>
Subject: Re: Need help in porting KASAN for 32 bit ARM on 5.4 kernel
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Linus Walleij <linus.walleij@linaro.org>
Content-Type: multipart/alternative; boundary="00000000000068713305a6cf33f9"
X-Original-Sender: venkat.rajuece@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=nUFa1pAN;       spf=pass
 (google.com: domain of venkat.rajuece@gmail.com designates
 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=venkat.rajuece@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--00000000000068713305a6cf33f9
Content-Type: text/plain; charset="UTF-8"

Thank you Dimity.

Target is ARM 32 bit based V7.
below are the configs apart from the above patches enabled on kernel.


CONFIG_KASAN_SHADOW_OFFSET=0x5f000000
CONFIG_HAVE_ARCH_KASAN=y
CONFIG_CC_HAS_KASAN_GENERIC=y
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=1
# CONFIG_TEST_KASAN is not set


After patching all the changes above my target is stuck @ bytes_is_nonzero
  after start_kernel, Please find below stack frame..


bytes_is_nonzero(inline)
  start = 0x6F1754AC -> 0

memory_is_nonzero(inline)
  start = 0x6F1754AC

memory_is_poisoned_n(inline)

memory_is_poisoned(inline)

check_memory_region_inline(inline)

check_memory_region(
    addr = 2159715648,
    size = 34,
    write = FALSE,
    ret_ip = 2159637592)

memcpy(
    dest = 0x812D1820,
    src = 0x80BAA540,
    len = 34)

        check_memory_region((unsigned long)src, len, false, _RET_IP_);
memcpy(inline)

        return __builtin_memcpy(p, q, size);
vsnprintf(
    buf = 0x812D1820,
  ?,
    fmt = 0x80BAA562,
    args = ())
  str = 0x812D1820
  end = 0x812D1C00
  spec = (type = 0, field_width = 0, flags = 0, base = 0, precision = 0)
  read = 34
  __warned = FALSE

        return __builtin_memcpy(p, q, size);
vscnprintf(
  ?,
    size = 992,
  ?,
i = ???

        int i;

        i = vsnprintf(buf, size, fmt, args);
vprintk_store(
    facility = 0,
    level = -1,
    dict = 0x0,
    dictlen = 0,
    fmt = 0x80BAA540,
    args = ())
  textbuf = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  text = 0x812D1820
  lflags = 0

        /*
         * The printf needs to come first; we need the syslog
         * prefix which might be passed-in as a parameter.
         */
        text_len = vscnprintf(text, sizeof(textbuf), fmt, args);
vprintk_emit(
    facility = ???,
  ?,
    dict = ???,
    dictlen = ???,
    fmt = 0x80BAA540,
    args = ())
  printed_len = 0
  curr_log_seq = 0

        printed_len = vprintk_store(facility, level, dict, dictlen, fmt,
args);
vprintk_default(
  ?,
  ?)

        int r;

#ifdef CONFIG_KGDB_KDB
        /* Allow to pass printk() to kdb but avoid a recursion. */
        if (unlikely(kdb_trap_printk && kdb_printf_cpu < 0)) {
                r = vkdb_printf(KDB_MSGSRC_PRINTK, fmt, args);
                return r;

#endif
        r = vprintk_emit(0, LOGLEVEL_DEFAULT, NULL, 0, fmt, args);
printk(
    fmt = 0x80BAA540)
  args = ()

        r = vprintk_func(fmt, args);
start_kernel()
  command_line = 0x812A7000

        smp_setup_processor_id();
end of frame

Thanks,
Venkat Sana.


On Fri, May 29, 2020 at 12:59 PM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Fri, May 29, 2020 at 5:39 PM Raju Sana <venkat.rajuece@gmail.com>
> wrote:
> >
> > Hello All,
> >
> > I started   porting
> https://github.com/torvalds/linux/compare/master...ffainelli:kasan-v7?expand=1
> >
> > to one out target , compilation seems fine but  target is not booting ,
> >
> > Any help can be greatly appreciated
> >
> > Thanks,
> > Venkat Sana
>
> Hi Venkat,
>
> +Linus, Abbott who implemented KASAN for ARM (if I am not mistaken).
>
> However, you need to provide more details. There is not much
> information to act on.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BdZkanWfzQ-dYMvqW5BG_bsxk-km-B-1r%2Bvv7HjD3-cDOfxrA%40mail.gmail.com.

--00000000000068713305a6cf33f9
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Thank you Dimity.<div><br></div><div>Target is ARM 32 bit =
based V7.</div><div>below are the configs apart from the above patches enab=
led on kernel.</div><div><br></div><div><br></div><div>CONFIG_KASAN_SHADOW_=
OFFSET=3D0x5f000000<br>CONFIG_HAVE_ARCH_KASAN=3Dy<br>CONFIG_CC_HAS_KASAN_GE=
NERIC=3Dy<br>CONFIG_KASAN=3Dy<br>CONFIG_KASAN_GENERIC=3Dy<br>CONFIG_KASAN_O=
UTLINE=3Dy<br># CONFIG_KASAN_INLINE is not set<br>CONFIG_KASAN_STACK=3D1<br=
># CONFIG_TEST_KASAN is not set<br></div><div><br></div><div><br></div><div=
>After patching all the changes above my target is stuck=C2=A0@

bytes_is_nonzero

=C2=A0 after start_kernel, Please find below stack frame..</div><div><br></=
div><div><br></div><div>bytes_is_nonzero(inline)<br>=C2=A0 start =3D 0x6F17=
54AC -&gt; 0<br><br>memory_is_nonzero(inline)<br>=C2=A0 start =3D 0x6F1754A=
C<br><br>memory_is_poisoned_n(inline)<br><br>memory_is_poisoned(inline)<br>=
<br>check_memory_region_inline(inline)<br><br>check_memory_region(<br>=C2=
=A0 =C2=A0 addr =3D 2159715648,<br>=C2=A0 =C2=A0 size =3D 34,<br>=C2=A0 =C2=
=A0 write =3D FALSE,<br>=C2=A0 =C2=A0 ret_ip =3D 2159637592)<br><br>memcpy(=
<br>=C2=A0 =C2=A0 dest =3D 0x812D1820,<br>=C2=A0 =C2=A0 src =3D 0x80BAA540,=
<br>=C2=A0 =C2=A0 len =3D 34)<br><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 check_memo=
ry_region((unsigned long)src, len, false, _RET_IP_);<br>memcpy(inline)<br><=
br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 return __builtin_memcpy(p, q, size);<br>vsnp=
rintf(<br>=C2=A0 =C2=A0 buf =3D 0x812D1820,<br>=C2=A0 ?,<br>=C2=A0 =C2=A0 f=
mt =3D 0x80BAA562,<br>=C2=A0 =C2=A0 args =3D ())<br>=C2=A0 str =3D 0x812D18=
20<br>=C2=A0 end =3D 0x812D1C00<br>=C2=A0 spec =3D (type =3D 0, field_width=
 =3D 0, flags =3D 0, base =3D 0, precision =3D 0)<br>=C2=A0 read =3D 34<br>=
=C2=A0 __warned =3D FALSE<br><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 return __built=
in_memcpy(p, q, size);<br>vscnprintf(<br>=C2=A0 ?,<br>=C2=A0 =C2=A0 size =
=3D 992,<br>=C2=A0 ?,<br>i =3D ???<br><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 int i=
;<br><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 i =3D vsnprintf(buf, size, fmt, args);=
<br>vprintk_store(<br>=C2=A0 =C2=A0 facility =3D 0,<br>=C2=A0 =C2=A0 level =
=3D -1,<br>=C2=A0 =C2=A0 dict =3D 0x0,<br>=C2=A0 =C2=A0 dictlen =3D 0,<br>=
=C2=A0 =C2=A0 fmt =3D 0x80BAA540,<br>=C2=A0 =C2=A0 args =3D ())<br>=C2=A0 t=
extbuf =3D (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, =
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, =
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0<br>=C2=A0 text =3D 0x812D1820<br>=C2=A0 lfl=
ags =3D 0<br><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 /*<br>=C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0* The printf needs to come first; we need the syslog<br>=C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0* prefix which might be passed-in as a parameter=
.<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0*/<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 te=
xt_len =3D vscnprintf(text, sizeof(textbuf), fmt, args);<br>vprintk_emit(<b=
r>=C2=A0 =C2=A0 facility =3D ???,<br>=C2=A0 ?,<br>=C2=A0 =C2=A0 dict =3D ??=
?,<br>=C2=A0 =C2=A0 dictlen =3D ???,<br>=C2=A0 =C2=A0 fmt =3D 0x80BAA540,<b=
r>=C2=A0 =C2=A0 args =3D ())<br>=C2=A0 printed_len =3D 0<br>=C2=A0 curr_log=
_seq =3D 0<br><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 printed_len =3D vprintk_store=
(facility, level, dict, dictlen, fmt, args);<br>vprintk_default(<br>=C2=A0 =
?,<br>=C2=A0 ?)<br><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 int r;<br><br>#ifdef CON=
FIG_KGDB_KDB<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 /* Allow to pass printk() to kd=
b but avoid a recursion. */<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 if (unlikely(kdb=
_trap_printk &amp;&amp; kdb_printf_cpu &lt; 0)) {<br>=C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 r =3D vkdb_printf(KDB_MSGSRC_PRINTK, fmt=
, args);<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 return =
r;<br></div><div><br></div><div>#endif<br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 r =3D=
 vprintk_emit(0, LOGLEVEL_DEFAULT, NULL, 0, fmt, args);<br>printk(<br>=C2=
=A0 =C2=A0 fmt =3D 0x80BAA540)<br>=C2=A0 args =3D ()<br><br>=C2=A0 =C2=A0 =
=C2=A0 =C2=A0 r =3D vprintk_func(fmt, args);<br>start_kernel()<br>=C2=A0 co=
mmand_line =3D 0x812A7000<br><br>=C2=A0 =C2=A0 =C2=A0 =C2=A0 smp_setup_proc=
essor_id();<br>end of frame<br></div><div><br></div><div>Thanks,</div><div>=
Venkat Sana.</div><div><br></div></div><br><div class=3D"gmail_quote"><div =
dir=3D"ltr" class=3D"gmail_attr">On Fri, May 29, 2020 at 12:59 PM Dmitry Vy=
ukov &lt;<a href=3D"mailto:dvyukov@google.com">dvyukov@google.com</a>&gt; w=
rote:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0px 0px 0p=
x 0.8ex;border-left:1px solid rgb(204,204,204);padding-left:1ex">On Fri, Ma=
y 29, 2020 at 5:39 PM Raju Sana &lt;<a href=3D"mailto:venkat.rajuece@gmail.=
com" target=3D"_blank">venkat.rajuece@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Hello All,<br>
&gt;<br>
&gt; I started=C2=A0 =C2=A0porting <a href=3D"https://github.com/torvalds/l=
inux/compare/master...ffainelli:kasan-v7?expand=3D1" rel=3D"noreferrer" tar=
get=3D"_blank">https://github.com/torvalds/linux/compare/master...ffainelli=
:kasan-v7?expand=3D1</a><br>
&gt;<br>
&gt; to one out target , compilation seems fine but=C2=A0 target is not boo=
ting ,<br>
&gt;<br>
&gt; Any help can be greatly appreciated<br>
&gt;<br>
&gt; Thanks,<br>
&gt; Venkat Sana<br>
<br>
Hi Venkat,<br>
<br>
+Linus, Abbott who implemented KASAN for ARM (if I am not mistaken).<br>
<br>
However, you need to provide more details. There is not much<br>
information to act on.<br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BdZkanWfzQ-dYMvqW5BG_bsxk-km-B-1r%2Bvv7HjD3-cDOfxr=
A%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CA%2BdZkanWfzQ-dYMvqW5BG_bsxk-km-B-1r%2Bvv7HjD3=
-cDOfxrA%40mail.gmail.com</a>.<br />

--00000000000068713305a6cf33f9--
