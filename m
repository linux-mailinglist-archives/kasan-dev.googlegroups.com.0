Return-Path: <kasan-dev+bncBCUMRQ6ZXQKBBMEJ5WBQMGQECCS6RPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 948A4363238
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 22:27:29 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 137-20020a250d8f0000b02904e7bf943359sf3010081ybn.23
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 13:27:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618691248; cv=pass;
        d=google.com; s=arc-20160816;
        b=JXNQPiRP5BU6YOV4mmJefz2CIGJcp2h+YP+2LXdUZU0dl8naSuw+60lhKlbbm0NIjT
         I2/65aNUBFr6fXO834ZxUllem32ngH1tPcr2mFWs3865+x6XuZUp/Biz6ehu3+BPlF4E
         l4wp5xG05XkHDFtZGFfBbdCH8vm+n5ZI9lzSaA02LGQwASFjG1EpzmfU4JDqvH7orGTx
         CuMaJyOWrROX65kR4CaQY2RW1nfMarE+CPV8S9giPF9LVW3jMz43PIAre2h66SomDS8n
         YvH5iI/YHMTKEtSaDQHeFUkxQ6J5Y45tMX5IA7LAdK3UZZX0S+rjtGjZ6VdfhVHc7Kzd
         cCgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=YVlUhtP0JleeZfzDTKTVtq5XBJKfJPLBDWrQyURmaSc=;
        b=rn9EESHbizmigJppSmNhrqQOuAImJnb+3emWPHgaRcNAv1Y2vucocrJF6vfgLSId82
         0iuKCt1sR7t74dWb3PM37/u7VTtyEz3K3Gcqzni363nvGEZAEqhm/KnhPgPKGgIF0Yzf
         LWZ7TZB6Hsj/ASvxIhPbSZHM685MQ6RpdRh3RNI/v/KCYpib6Pu3xSSE3XiM3dh+9Ic2
         rttoRNYn0+w67gm4yFXjsyMdAg/ffSiobDaxkjvrpLKVmh79VwPNlo6XeWaP505HsUzz
         NGvb2a6gFUIL0pocy8nQ3RFJDA+v2Pa7x501ggVdW1HCMCuKaEkTE2VQFFL8oy6MWDfK
         8caA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WepZCSPM;
       spf=pass (google.com: domain of tareq97@gmail.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=tareq97@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YVlUhtP0JleeZfzDTKTVtq5XBJKfJPLBDWrQyURmaSc=;
        b=WiWR5cWJLlWx485J+4yhrv6e7cKej8+tupR7hgecs/N6NXBGbU6uqWkw15aXUxIdok
         wPd3HnL/A10x6djVj8xaka8+x9ERe4GjskacB12OgMvBfObNMN1/Dlga1RmWX8JE3NK5
         QA2XpEWXwi4gjP6XzWg2dTxoX9ukwA6KL3geqzblauYToehu5IOZ6NBOnH8+iCZLdIB8
         pj7SQw0d9Lf/AzSi5nmuDuoHlhQ2xHOaSSYgTdOdjzj41DnGHGA6diFsccPBV/uNTrQW
         llxiRTDL4SEUxpo//WUgvUGke1ZNPTDncNENfFdOtgxKPKUpcOsHPAVIug45fwCEdq5M
         6BBA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YVlUhtP0JleeZfzDTKTVtq5XBJKfJPLBDWrQyURmaSc=;
        b=Lh1KbOkx6PciQJIoKGSoL7aP6kT3uI9654RQ8rH5UsDNDks3BG2wUVnoJf3IJWh0+W
         9UlovWb6TFxAtPqi689BUpGCmeohoS3gYOdlcZ3j56IWcxdStOVfra+9EyVjQK92n6XY
         J6l9/vV6K0cpIpjpBk7DU9e8WFoQA1BKzDYw6e5GGRhTSKR82nFZ5PMWTeRTguhZnybr
         7AXLkC+OwjNIjJWX4NKiHunwQVjEUohm5h6sPas/GiyxM3tFPacUeNZouWEVUNKuyFji
         2hxkqw5DLym7D1nvuJWtrxvhDu8fpRL8MwkMcnSy0g3vi5l9YeH0oKSX19xVUGzu8N/l
         tFrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YVlUhtP0JleeZfzDTKTVtq5XBJKfJPLBDWrQyURmaSc=;
        b=TT4PqpZcYbGvmEpUPQtTbp3QvwCtWwDo+4YNu9uxXEHHh0rcrE4vi/AUp0PblXCi6E
         T/1YeS5f5nect/YQoxgJyNO91ou9ObMQXRCtfJ9oPjUZ3abAJGgMoBZCYUwk3Y78/3XS
         Zwn1JcppjaZ4l6mqHJCSi/WUHtWfEtrTu0iPxf2Q2kuASdw9mNER1JqMhlg2KpLBZDtv
         MnhL8elJVaSP6t1CVjEM4FzKo3ejQ8RQe2FuA0EPxSX6HK/1qEcStQXeDPLL0AFQCbXV
         T2AbabP3u1SqVF2BhKcTCW/3DVJMj+2nYy0zL0u3DZo0dhpmX+p3s650imNbz9pqDZZl
         /Tkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530K0URnIO4bXAhXb2MxIkZ6zLJ3JTozCJx4KGKJPPG+wxM/IOxS
	naQQxJBuJjq9YQn8sFUHpJM=
X-Google-Smtp-Source: ABdhPJx2EvTSjrqIXl3FHLr5NqxtwKdCqZ1tbqAgGw2QiT4/VJBpzcZCZsWYA6zar/gcXK9TaqlxnA==
X-Received: by 2002:a25:bc8b:: with SMTP id e11mr7642953ybk.115.1618691248417;
        Sat, 17 Apr 2021 13:27:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7bc7:: with SMTP id w190ls3068503ybc.2.gmail; Sat, 17
 Apr 2021 13:27:28 -0700 (PDT)
X-Received: by 2002:a5b:303:: with SMTP id j3mr6846468ybp.433.1618691248018;
        Sat, 17 Apr 2021 13:27:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618691248; cv=none;
        d=google.com; s=arc-20160816;
        b=D+JaWg963o0O0Q4GmgsMkl/AmTOSyFlh4x2FzQWK+AXJLnHRv7VXUBlS5uEMHFnJkf
         EFnIg+lqSkYs8SW++ua4ZXulaALKmOtbEy9j7UbLqyhdP2T4EPsFiQX6XbWH39WRJxle
         gErQ7ayOdaMH+Hxv+ANWGmlv3yonhWXVuR3ci2UG6cljlL3iSN5ss5zPPnMRacYlbZUa
         h6MWM2fICXEAlsD8veGA/+zNGGRgGD/eeCtxlh5IwBMq0ApxUgNAxyLNKy5YyIiPulb4
         FTGtrrePf8ASpWAW5DCjvj54Y5gIF1LLMiCchbvG3ejmnWN7+ASlqD1YXORvnliYJ5MQ
         x7YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nndp52Azgt69jPDCIlxW9DZPtlp2NT4Rawdhmtwfz9A=;
        b=MsdkExwrbLliZGZt89paM24LOo8/yyw63TsMNJl6p0LxS+QfaX2sQowSavyOBstRMf
         tY7+UdZgLi1NZiFJRyoNN6bYjMe+1ksIJGB/3aa3zUFaemhMYzunCHNvCtsiEaRDVkT2
         hx3/4FJzXvoHU6YvUdjSRSby5QvcSCKshoV8jhn9G5uRulrBxvAGTA5rqUsLzkrbDZK6
         +ILaYuX9p3J61Heih9hJk24HEh51FIpZ026EE2trAOzJBHWTBHo5sNQ81JplLdtKsnZw
         ckxRZkYITiQX4/ixwx0foImDSPT54egvOkYXZT3urAHmhAHTBPjwWS8FX/4SjqONe9Rx
         JKxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=WepZCSPM;
       spf=pass (google.com: domain of tareq97@gmail.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=tareq97@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id f13si390625ybp.0.2021.04.17.13.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Apr 2021 13:27:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of tareq97@gmail.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id s19so8492305uaq.4
        for <kasan-dev@googlegroups.com>; Sat, 17 Apr 2021 13:27:28 -0700 (PDT)
X-Received: by 2002:ab0:7186:: with SMTP id l6mr1832524uao.117.1618691247711;
 Sat, 17 Apr 2021 13:27:27 -0700 (PDT)
MIME-Version: 1.0
References: <0faf889d-ac2d-413f-826e-6c2f5bf5aaf2n@googlegroups.com> <CACT4Y+ZHyat_KE+yQ5z7xpF+RfW39tbpYS6t=9A82dvbZcuuKQ@mail.gmail.com>
In-Reply-To: <CACT4Y+ZHyat_KE+yQ5z7xpF+RfW39tbpYS6t=9A82dvbZcuuKQ@mail.gmail.com>
From: Tareq Nazir <tareq97@gmail.com>
Date: Sat, 17 Apr 2021 22:27:16 +0200
Message-ID: <CAHUigpxrNQYOBoRGWZqYaKEoUDH1mkPw9pyW0iPdLSU9T+r4OQ@mail.gmail.com>
Subject: Re: Regarding using the KASAN for other OS Kernel testing other that LInux
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="000000000000d22a3d05c030ec6f"
X-Original-Sender: tareq97@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=WepZCSPM;       spf=pass
 (google.com: domain of tareq97@gmail.com designates 2607:f8b0:4864:20::930 as
 permitted sender) smtp.mailfrom=tareq97@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000d22a3d05c030ec6f
Content-Type: text/plain; charset="UTF-8"

Dear Dmitry Vyukov,

Thanks for the reply,

I have few questions as listed below

1 ) I would like to know if there is any open source repo that has adapted
KASAN for running it on the BSDs or Fuchsia kernels.

2) Oh so what I was able to understand from your statement was the current
implementation of KASAN is only specific to Linux kernel but it can be
adapted to other kernels as well. It is the same analogy as implementing
American Fuzzy lop fuzzer for running its new language programs. Just let
me know if I am right on this or not?

Thanks and Regards
Tareq Mohammed Nazir

On Sat, Apr 17, 2021 at 12:28 PM Dmitry Vyukov <dvyukov@google.com> wrote:

> On Fri, Apr 16, 2021 at 9:50 PM Tareq Nazir <tareq97@gmail.com> wrote:
> >
> > Hi,
> >
> > Would like to know if I can use KASAN to find bugs of other open source
> Real time operating systems other than linux kernels.
>
> Hi Tareq,
>
> The Linux KASAN itself is part of the Linux kernel codebase and is
> highly integrated into the code base, it's not separate and something
> directly reusable. Think of, say, Linux TCP/IP stack implementation.
> However, the idea, algorithm and compiler instrumentation is perfectly
> reusable and KASAN is ported to several BSDs and Fuchsia kernels at
> least.
>


-- 
Thanks and Regards,

Tareq Mohammed Nazir
tareq97@gmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHUigpxrNQYOBoRGWZqYaKEoUDH1mkPw9pyW0iPdLSU9T%2Br4OQ%40mail.gmail.com.

--000000000000d22a3d05c030ec6f
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>Dear Dmitry Vyukov,</div><div><br></div><div>Thanks f=
or the reply, <br></div><div><br></div><div>I have few questions as listed =
below<br></div><div><br></div><div>1 ) I would like to know if there is any=
 open source repo that has adapted KASAN for running it on the BSDs or Fuch=
sia kernels.</div><div><br></div><div>2) Oh so what I was able to understan=
d from your statement was the current implementation of KASAN is only speci=
fic to Linux kernel but it can be adapted to other kernels as well. It is t=
he same analogy as implementing American Fuzzy lop fuzzer for running its n=
ew language programs. Just let me know if I am right on this or not? <br></=
div><div><br></div><div>Thanks and Regards</div><div>Tareq Mohammed Nazir<b=
r></div></div><br><div class=3D"gmail_quote"><div dir=3D"ltr" class=3D"gmai=
l_attr">On Sat, Apr 17, 2021 at 12:28 PM Dmitry Vyukov &lt;<a href=3D"mailt=
o:dvyukov@google.com">dvyukov@google.com</a>&gt; wrote:<br></div><blockquot=
e class=3D"gmail_quote" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px s=
olid rgb(204,204,204);padding-left:1ex">On Fri, Apr 16, 2021 at 9:50 PM Tar=
eq Nazir &lt;<a href=3D"mailto:tareq97@gmail.com" target=3D"_blank">tareq97=
@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Hi,<br>
&gt;<br>
&gt; Would like to know if I can use KASAN to find bugs of other open sourc=
e Real time operating systems other than linux kernels.<br>
<br>
Hi Tareq,<br>
<br>
The Linux KASAN itself is part of the Linux kernel codebase and is<br>
highly integrated into the code base, it&#39;s not separate and something<b=
r>
directly reusable. Think of, say, Linux TCP/IP stack implementation.<br>
However, the idea, algorithm and compiler instrumentation is perfectly<br>
reusable and KASAN is ported to several BSDs and Fuchsia kernels at<br>
least.<br>
</blockquote></div><br clear=3D"all"><br>-- <br><div dir=3D"ltr" class=3D"g=
mail_signature"><div dir=3D"ltr"><div>Thanks and Regards,</div><div><br></d=
iv><div>Tareq Mohammed Nazir</div><div><a href=3D"mailto:tareq97@gmail.com"=
 target=3D"_blank">tareq97@gmail.com</a></div><div><br></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAHUigpxrNQYOBoRGWZqYaKEoUDH1mkPw9pyW0iPdLSU9T%2Br4OQ%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAHUigpxrNQYOBoRGWZqYaKEoUDH1mkPw9pyW0iPdLSU9T%2B=
r4OQ%40mail.gmail.com</a>.<br />

--000000000000d22a3d05c030ec6f--
