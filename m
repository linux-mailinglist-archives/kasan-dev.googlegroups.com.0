Return-Path: <kasan-dev+bncBDK23E7J5QOBBW6SXDXQKGQEHHQOTEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 84D68116B9E
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2019 12:00:44 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id v26sf3209597ljg.22
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 03:00:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575889244; cv=pass;
        d=google.com; s=arc-20160816;
        b=pn7gFA58NwRwmV5D+wYOlCVkpNZhzIML8M7VB05UZ/Jx57HOXbOc0pLOSUr8H4B3UW
         do8AcUV7JL1FJDobbPP9cyZF0zrIa6+H8JINDiqjDnh8wo1eaYHZj6HEg1zj30gurwxn
         DUKAdVC2nyDFy4qLQxm/Vih+vS5rgihGLbhZ1ymPbo+DzLFmDAQDwfUeWZAGIr4/jHGx
         F65aqmOt131cIlkEjWHfBESDNzyFur2OsOMmAT6o6xGZmiyTIlJeiJIoxJvul3LMW3pL
         MKO0eroPoR3zPBOaMdJWeUZC/frIKnDE6d8b1Uaop5qsyNVTw/Avd4n3GCk+FZmiQ7B+
         +qDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :user-agent:date:message-id:autocrypt:openpgp:cc:to:subject:from
         :sender:dkim-signature:dkim-signature;
        bh=C2xhK/K7a3kzvzl9ZGzNqti42LkAAFhB+NIr/ym9vRU=;
        b=NkleLbIIOxd/L9zgPkpeakKxGIdUyNiIIFouHE+vtSwT74K2GYkCphTi9l1XX6udmU
         8C8XrooW6rruaM95QjyjtV9WPxKhoUJQ2UzA/OWxCzT9ferXK9ycL4FS50vfjNqlQHtv
         9FqNaUeYKu1RA5DkPk+P/Nrv+K1xEFJMLYQp2sbrs8fjV4XRtaJfrGGMgrdgVGHdN30b
         MrTANjDgHS8Ro1UReJa0qr0BYpdSUnr0hAz8ZI71O0JrszfhNHkYoGpKi8I1x8aRi/kV
         boAClY4PpHdx+oXyZbU8BXGRKBwB8R4x/7ZttEve84cMe6l78DPEwwZgB8MUvj0erl77
         I3pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="T/u/dh19";
       spf=pass (google.com: domain of romanek.adam@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=romanek.adam@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:to:cc:openpgp:autocrypt:message-id:date
         :user-agent:mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C2xhK/K7a3kzvzl9ZGzNqti42LkAAFhB+NIr/ym9vRU=;
        b=nOBwFQtnpFLO/yc7RPDpVCLBRzVzIewolPdI9O/4+MWeRzsgDFWdtLkdukTrDDsRZf
         3xCIJyAu4wNcEBaOzTviPstyPDNKMUT2kNZNGJqrfu2DvNMQAhd1BiQkDIkk2p8BRXCC
         ziOUKeH/e497jQdP6pFsGrVM8HeYLLwzV2av55+FlZTrn8AeNa3+pETJGf9fo2nuSy8j
         2WdhYmjR/261dS2Eqb+wKXphDcxBRsFxzamFKwNaUALotrpDSLWYzWFcEVsmCJJJvXV5
         KewBDg1NNhLV9fGxMHgAxLq6w3Suq54iceuium1pAEI5d3zv31eJH9qYz4atQDSIqv3+
         PWqg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:subject:to:cc:openpgp:autocrypt:message-id:date:user-agent
         :mime-version:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C2xhK/K7a3kzvzl9ZGzNqti42LkAAFhB+NIr/ym9vRU=;
        b=imQQvtsXsNhLCjCZqJdyYPiqL/1Z+wbXeUQRnfU6NFtHCtRJKYk3gc8xLVSYC24TKS
         bGiRUV104CTrUohszVowQn2dfReASEk1FB2n1b26y0D9T53PvbfVr0SvNXKV83ItZP2K
         4frJHWRztAsxxFysSVTHr6RJeRjeC6Pess9QvYTz/szLPN7v2B54La6IwqNr3Fn6tVVT
         aSUowuUVUlMtLreOWiu43xTLcboU70gy+jgutikI9YAmO/jRWG7QGQinrch15CLJresv
         riI/CWod11UOUjvziPS67gHdCkHvFU+NhiTm5fXLE0VHS9dieM0B0ssduU0h9FL4NaSa
         8Y6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:to:cc:openpgp:autocrypt
         :message-id:date:user-agent:mime-version:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C2xhK/K7a3kzvzl9ZGzNqti42LkAAFhB+NIr/ym9vRU=;
        b=LsNjdr0yfWIYPwmopUVbNf+P0eEgL42gTXBSPOI1WQKS42milAfqIzDmdcfnulD66V
         RyX7YxHws9tTtrLfNY6kj39ptfdAZfjhXtVEjksmtXORkGsOaX+Yl5qpVDO8Jhraw1MH
         srMKOfMjfx5JP2+LEL2HlCs72xfrS8aDfZgr49GMw9v1CvwYVSsY9+g3v6LDNqKocUN3
         pFXnt2AYTadXfZ7dCRLDBcPYLN9eKCuBZAfrPOHu4pPpuY1HQgjWxrMJ9EVgVvlkl0Y1
         B4Rgo7Pukngh+hByPT3VHqA/EK4MbMjXFzi/Y0NfNSIc+6ZE0wRdcOKqjP/KGQKSbUXV
         sT0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUwZ3HgMqAsPdXJFJJTwhgc6nBkZ7sKtFVqjieAfdbRC1OWEE7I
	LVGb9hO8y8AF9ldoORdaxis=
X-Google-Smtp-Source: APXvYqzYGtfTOZQeN9Zw5mAPc6xi5wlX29xIig2SyNX72U0XjVmyjhMt/DcgiLzFV9Nhh49FrAIwkg==
X-Received: by 2002:a19:3f16:: with SMTP id m22mr14550069lfa.116.1575889244019;
        Mon, 09 Dec 2019 03:00:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b4e7:: with SMTP id s7ls1871124ljm.10.gmail; Mon, 09 Dec
 2019 03:00:43 -0800 (PST)
X-Received: by 2002:a2e:2418:: with SMTP id k24mr17067072ljk.49.1575889243189;
        Mon, 09 Dec 2019 03:00:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575889243; cv=none;
        d=google.com; s=arc-20160816;
        b=pwRIBXRP3als5itAhSHTtU+YZNGlwCqlAlE6Gf6+ymv4Q1qRicKsVCkwzwehgYxxV9
         jV/HjbHs4xYsz6iWzc2RMHsaK496qfzF3jbKUP+BUE0SoG9fAlEyzclBjcyLrETJhXpN
         4EoSVM//Ed3QsO6CKWJDuiX8NssEWJoNv7CnB62/ZM2H7GjFRV1QeFfIO47+PTSRLVXQ
         58Vr1U+9bt6R5zzZcO1uRzQ2mDAok12fkuAhPzvb89ALQk2ofoAmi32rzjm3jeVlbI9u
         TC3mhRnky3I7C4ykGJrKTRnraoSFkwnD6fM2/tiLAYomsfI8bx0MhdnGDJxVcXpJAsf2
         ZI8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:mime-version:user-agent:date:message-id:autocrypt
         :openpgp:cc:to:subject:from:dkim-signature;
        bh=9nVM2WXQlwmBNUh7i3BgH/NX9TLBlA9M18ShSEgKSeA=;
        b=kM/t8alpc1jtczKYRybPyOIIgE52zmdsU/OSQGqO7IWD83aQsQx7mchEM5gLfIflke
         reo0mnF0a8E/kaOXkrpAgfuLDx0PyrxXjOLn/OAvpyqX7EyuK2M8/waXlgg3p3Yf8hZr
         Ym/GJyUxlj5UsVYgFBduNDrBqeOtbYOnMP63isdjLtbAuElDDwMAc+rClkWUS3wpnX2Z
         RwNsZG1eAHogIZ1zv9xJ3jW9AJklIFSjCqfx+2wDBuVx1RQuqdaFPhX7RrdxQ11p1Ff1
         46f867nCh25QZL9XZMEtcaV5Ee0qcOD50LdppnlLPg/pDWYiyHXtpRgl4ZkS0lOn5fLH
         Ex/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="T/u/dh19";
       spf=pass (google.com: domain of romanek.adam@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) smtp.mailfrom=romanek.adam@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12d.google.com (mail-lf1-x12d.google.com. [2a00:1450:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id o24si1647167lji.4.2019.12.09.03.00.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 03:00:43 -0800 (PST)
Received-SPF: pass (google.com: domain of romanek.adam@gmail.com designates 2a00:1450:4864:20::12d as permitted sender) client-ip=2a00:1450:4864:20::12d;
Received: by mail-lf1-x12d.google.com with SMTP id m30so10322452lfp.8
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 03:00:43 -0800 (PST)
X-Received: by 2002:ac2:5503:: with SMTP id j3mr146194lfk.104.1575889242578;
        Mon, 09 Dec 2019 03:00:42 -0800 (PST)
Received: from [192.168.15.145] (clk-3.netdrive.pl. [185.24.27.3])
        by smtp.gmail.com with ESMTPSA id u16sm12211043lfi.36.2019.12.09.03.00.41
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Dec 2019 03:00:41 -0800 (PST)
From: Adam Romanek <romanek.adam@gmail.com>
Subject: KASAN for x86-32 and more
To: dvyukov@gmail.com
Cc: aryabinin@virtuozzo.com, kasan-dev@googlegroups.com
Openpgp: preference=signencrypt
Autocrypt: addr=romanek.adam@gmail.com; prefer-encrypt=mutual; keydata=
 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
 KkgCY1AxMySCSuuaJqk=
Message-ID: <f691fe31-aeba-b702-88f2-54c920e81250@gmail.com>
Date: Mon, 9 Dec 2019 12:00:40 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
Content-Type: multipart/alternative;
 boundary="------------22A0D3D86346F5B2C5039C39"
Content-Language: en-US
X-Original-Sender: romanek.adam@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="T/u/dh19";       spf=pass
 (google.com: domain of romanek.adam@gmail.com designates 2a00:1450:4864:20::12d
 as permitted sender) smtp.mailfrom=romanek.adam@gmail.com;       dmarc=pass
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

This is a multi-part message in MIME format.
--------------22A0D3D86346F5B2C5039C39
Content-Type: text/plain; charset="UTF-8"

Hi Dmitry,

My name is Adam Romanek. I'm a software engineer, currently working for
Liberty Global. I'm putting Andrey Ryabinin on CC, as I was in contact
with him last year regarding this topic.

More than a year ago I did a port of the initial version of KASAN based
on Linux 4.0 and the initial work by Andrey on Linux 3.x, from x86-64 to
Linux 3.12.X and x86-32. I was always seeking to port the x86-32 code to
the most recent Linux version and eventually make it public but didn't
have the time.

Quite recently I did the job - I have the code ported and running on
Linux next from December, some KASAN tests pass but some don't. I still
didn't have the chance to analyze it, I simply ported what I had done a
year ago for our project - we had basic KASAN with stack and globals
covered. Also I had to cut some corners in the code to make it work, so
it needs some further polishing for sure. I saw some recent changes by
Daniel Axtens [1] which potentially can make my code easier to fix (on
x86-32 modules and vmalloc occupy the same virtual address space, so I
had to deal with it somehow, but it's not something which can be
upstreamed).

Just a few days ago I noticed in kernel.org Bugzilla that you're
maintaining the "sanitize" component in "memory management" product.
Just as you did, I also noticed it's hard to evaluate whether KASAN
tests pass or fail (and how many of them do pass/fail).

Now to the point. I'm a software engineer with 10+ years of experience,
although I have minimal coding experience in the Linux kernel, not to
mention upstreaming. This port of KASAN to x86-32 and an older Linux was
practically my initial attempt to make changes in the Linux kernel :) I
have rather little spare time but I think I could contribute some
improvements around KASAN. I could start with this tests related task
[2], then maybe I could dig into some more advanced stuff. Of course I
would need to familiarize myself with the upstreaming process too.

In the meantime I was hoping to share and potentially polish my x86-32
code for KASAN. Do you think there would be interest from the community
in it? I mean the x86-32 arch is rather not that important anymore, so I
want to avoid putting more effort in something which would eventually
get rejected.

Please share your thoughts.

[1] https://lore.kernel.org/linux-mm/20191031093909.9228-2-dja@axtens.net/#r
[2] https://bugzilla.kernel.org/show_bug.cgi?id=198441

Best regards,
Adam Romanek

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f691fe31-aeba-b702-88f2-54c920e81250%40gmail.com.

--------------22A0D3D86346F5B2C5039C39
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta http-equiv=3D"content-type" content=3D"text/html; charset=3DUTF-8=
">
  </head>
  <body text=3D"#000000" bgcolor=3D"#FFFFFF">
    <p>Hi Dmitry,</p>
    <p>My name is Adam Romanek. I'm a software engineer, currently
      working for Liberty Global. I'm putting Andrey Ryabinin on CC, as
      I was in contact with him last year regarding this topic.<br>
    </p>
    <p>More than a year ago I did a port of the initial version of KASAN
      based on Linux 4.0 and the initial work by Andrey on Linux 3.x,
      from x86-64 to Linux 3.12.X and x86-32. I was always seeking to
      port the x86-32 code to the most recent Linux version and
      eventually make it public but didn't have the time.</p>
    <p>Quite recently I did the job - I have the code ported and running
      on Linux next from December, some KASAN tests pass but some don't.
      I still didn't have the chance to analyze it, I simply ported what
      I had done a year ago for our project - we had basic KASAN with
      stack and globals covered. Also I had to cut some corners in the
      code to make it work, so it needs some further polishing for sure.
      I saw some recent changes by Daniel Axtens [1] which potentially
      can make my code easier to fix (on x86-32 modules and vmalloc
      occupy the same virtual address space, so I had to deal with it
      somehow, but it's not something which can be upstreamed).<br>
    </p>
    <p>Just a few days ago I noticed in kernel.org Bugzilla that you're
      maintaining the "sanitize" component in "memory management"
      product. Just as you did, I also noticed it's hard to evaluate
      whether KASAN tests pass or fail (and how many of them do
      pass/fail).</p>
    <p>Now to the point. I'm a software engineer with 10+ years of
      experience, although I have minimal coding experience in the Linux
      kernel, not to mention upstreaming. This port of KASAN to x86-32
      and an older Linux was practically my initial attempt to make
      changes in the Linux kernel :) I have rather little spare time but
      I think I could contribute some improvements around KASAN. I could
      start with this tests related task [2], then maybe I could dig
      into some more advanced stuff. Of course I would need to
      familiarize myself with the upstreaming process too.<br>
    </p>
    <p>In the meantime I was hoping to share and potentially polish my
      x86-32 code for KASAN. Do you think there would be interest from
      the community in it? I mean the x86-32 arch is rather not that
      important anymore, so I want to avoid putting more effort in
      something which would eventually get rejected.</p>
    <p>Please share your thoughts.<br>
    </p>
    <p>[1] <a
href=3D"https://lore.kernel.org/linux-mm/20191031093909.9228-2-dja@axtens.n=
et/#r"
        moz-do-not-send=3D"true">https://lore.kernel.org/linux-mm/201910310=
93909.9228-2-dja@axtens.net/#r</a><br>
      [2] <a href=3D"https://bugzilla.kernel.org/show_bug.cgi?id=3D198441"
        moz-do-not-send=3D"true">https://bugzilla.kernel.org/show_bug.cgi?i=
d=3D198441</a></p>
    <p>Best regards,<br>
      Adam Romanek<br>
    </p>
  </body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/f691fe31-aeba-b702-88f2-54c920e81250%40gmail.com?utm_m=
edium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-=
dev/f691fe31-aeba-b702-88f2-54c920e81250%40gmail.com</a>.<br />

--------------22A0D3D86346F5B2C5039C39--
