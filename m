Return-Path: <kasan-dev+bncBAABBSOSZHXQKGQER2XC2CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id D946811D220
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 17:22:34 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id ec1sf1799617qvb.6
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 08:22:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576167753; cv=pass;
        d=google.com; s=arc-20160816;
        b=PKJWmnyalwxQvwCuKPHWCFSXd86Tz9NNhUw08iA7OAJZUp5jVWr2apyAq6lYx5/xRB
         xgtpRfgHgy+ABj5JeBnMuTSUi4cYtBB/lF9JrLWcUxtCGFNNfmblxdyETwct55WyhiQc
         r+IBVzRXmgkpK7630B5NSjnxewgHwYhA53Jokv5Y57XukoQZmGAGPGxamL8I6u1s0kWu
         20xy8TPnrHf5V/JQ/t7Mjay+QKX3owui6y4Fed7zmpJH8Xkb/InJXcEbNG1FLouCbxW+
         dQh8fSlckto0sa8/pJCOdpT7twMA5tbUMXOzJis0Nqb9A4CSMEEGJdMg1buKG+piG8HB
         faAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:content-language
         :in-reply-to:mime-version:user-agent:date:message-id:from:references
         :cc:to:subject:dmarc-filter:sender:dkim-signature;
        bh=csFPPiHYTF5OUYR6xNZzkKqQ54jPdGamGSO9xCwNFqo=;
        b=Q8Bjr3oXWkiwkIjRllQ8EIK27fMNBrhk8yJk/johusxo7BHHRDjAHtSZ+7/q/fYJhl
         jTCwNxB8eG1b9/xjZh9hWcjKQ9S8o6okxP3lY+B366dLAy3ucd3zHIKhCjiB9E9a+nJv
         +3C/qiXnlwJTunHo071r6gkLtzrrxqEencJ5bHtSrBwOHrohh3khKNZZ27LAEhJ31lNw
         zKW9EO9LBP3o+E5YYxQjr+hLlsSwSiV5e52X+ELStOvlDMOKWDQZna/8zf+69qx9oNAK
         6uLoZDA5cMyQgfZRcF/tV0wJGNwUJ9iK3R3eJX50S/luxblgc6HPmjE5R32ktwiZlFvm
         EOyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codeaurora.org header.s=zsmsymrwgfyinv5wlfyidntwsjeeldzt header.b=SVd1N9l0;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=F7kI2CPL;
       spf=pass (google.com: domain of 0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) smtp.mailfrom=0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-000000@us-west-2.amazonses.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:dmarc-filter:subject:to:cc:references:from:message-id:date
         :user-agent:mime-version:in-reply-to:content-language:feedback-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=csFPPiHYTF5OUYR6xNZzkKqQ54jPdGamGSO9xCwNFqo=;
        b=BOEmWMkgl1Y1sV5nS3tgn5ARneXCONyo9W0U9GUe/kwNLvw/+kRP8SGFFQ5tAne6kZ
         CsDmxgyIK5qjaN7FaChHEZYMOlF23VZ/EnenggivTjfc47Byfk8SSCwNFQjyKwa5o3pr
         DV3LFQzUSoq+CiUoUM7dODX8687q0AOjNh0FySq23wxutTfkSAf+7Boo/f/uqGhb/Cd6
         Q4riLteM9/DKqBnuZyzWRArAJnYCsbydPjLqlUFQmQgoEz8qJn5tcmkY+b/l8fFEtgve
         F2h6yrXlbJ/Hl1vO3ZRt5k62itiNp7yN2La7X9nwDyfHLeH+4MiiOJT1mo1JBuOFTC6d
         zHIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:dmarc-filter:subject:to:cc:references
         :from:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:feedback-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=csFPPiHYTF5OUYR6xNZzkKqQ54jPdGamGSO9xCwNFqo=;
        b=QSOU+5o9wILvjEQMPMo8ZgR8onSxhCGieMrh5z8J+vZW510T1seZjxFaMaSYVo4VqP
         Qix5MTvtY6XkLcb0NYFE96c7wBXNTnIy5PQrSZuutmtdvUDmx9d0ssj5yVn4pHrCXDQy
         V2hnt2SS4GpH9cm1CdXaXR84TzafHo+OOcqnvgK4uILYD8ep8ejL0YUKX3UYIoygyoOs
         D2sh+94dlWMDE7FANK2xYpVOkAjmripZEAAJtMfMnv1ev/MbzSSiG6M4+6s+CfJYasRh
         T93Stq8hIzbOQnxdBu/CsoIdBJjo8RtHp0MvHfyJJ4IMK1WZObRUWPnXep2UgqemrGsf
         +ysQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUiXhsYgnfZux3RGBNr4rBXHGkg7jTVZ6YBmjQDIqP5GkPHpCfu
	DDOEddt8Ipc7jTggnfTiFB4=
X-Google-Smtp-Source: APXvYqwvyqA0P69e4KyV8i3m5U7/mQv0NadZmFPIHO3y67apwV4zigZ5al1EET0nC5ozlQ8GfTKA5g==
X-Received: by 2002:ac8:5155:: with SMTP id h21mr8168037qtn.174.1576167753665;
        Thu, 12 Dec 2019 08:22:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:2746:: with SMTP id n67ls1977714qkn.8.gmail; Thu, 12 Dec
 2019 08:22:33 -0800 (PST)
X-Received: by 2002:a37:b0c5:: with SMTP id z188mr9120486qke.215.1576167753088;
        Thu, 12 Dec 2019 08:22:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576167753; cv=none;
        d=google.com; s=arc-20160816;
        b=0GBArNlvtQbw9Ri2iuWPxZc3W6Gt/F6p40M/zYXcMC8RKCEQGK7SmdkxlcHx42KI3B
         TvyRuWH+1zXI+mMDgcHYkRatlGCzxBYfYTr9gSlAjDe8lZmhPBS0DkM+P4FxTR1RlUzT
         zmYz5I88r0s2XxcTWxmiwBiCWcfvkOYczaIaTtstsA7lCbdqW25K9pB85QovvHHDsQx1
         ZmeLYvh8meSVluGfvAPQQro8DBriZI9AMNeq3afahVKe5CzIb/vgXStA9Rh+Lol4a9Ua
         NDp41AaKy68ZapXLBVqzckHFXSr8tNMKgP6DbDTGTimXaLUaPBpCuLh4kJEu40oxgymq
         vPcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-language:in-reply-to:mime-version:user-agent
         :date:message-id:from:references:cc:to:subject:dmarc-filter
         :dkim-signature:dkim-signature;
        bh=oVq/Akx/sX3E8AbIDrw3ZSi+t/+eN/d3H7q6JrGOiuA=;
        b=yYnTIj2G6TyJnGf682YVLxEzeDkOYDOk3k12jbZ6YtnM/wiFdjohbv/aw7acvu1Eh9
         QwVkHNBEk/rwZuFd+0/KzNWz8N5vD02DcKxqenIbUhZBED33a80rtQ5w7ZtnEi3jWYFS
         fnyXKAmx1dGFpm3KE8lorCWY9s4G3WZGbl6ACC556gUku52V0kDSg3uJ0ac+9Dk/fJpz
         2USQ1luYYj6KWbqr23NZ2rP+Thc+ZyFfriUxWOMKv0IXqz5xbCEArhIKGItPhBdWIJL7
         R+85oXT3LlG1iFc1/GP/HThtBiVLGAPfh2KGw6e/E9WF1vFBaVvAMOYM2etYfcZsQ6Ji
         u+jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codeaurora.org header.s=zsmsymrwgfyinv5wlfyidntwsjeeldzt header.b=SVd1N9l0;
       dkim=pass header.i=@amazonses.com header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=F7kI2CPL;
       spf=pass (google.com: domain of 0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) smtp.mailfrom=0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-000000@us-west-2.amazonses.com
Received: from a27-185.smtp-out.us-west-2.amazonses.com (a27-185.smtp-out.us-west-2.amazonses.com. [54.240.27.185])
        by gmr-mx.google.com with ESMTPS id d16si331668qtp.5.2019.12.12.08.22.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-SHA bits=128/128);
        Thu, 12 Dec 2019 08:22:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-000000@us-west-2.amazonses.com designates 54.240.27.185 as permitted sender) client-ip=54.240.27.185;
X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on
	aws-us-west-2-caf-mail-1.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.0 required=2.0 tests=ALL_TRUSTED,HTML_MESSAGE,
	SPF_NONE autolearn=unavailable autolearn_force=no version=3.4.0
DMARC-Filter: OpenDMARC Filter v1.3.2 smtp.codeaurora.org 3D17CC447A1
Subject: Re: KCSAN Support on ARM64 Kernel
To: Mark Rutland <mark.rutland@arm.com>, Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, sgrover@codeaurora.org,
 kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>,
 "Paul E. McKenney" <paulmck@linux.ibm.com>,
 Will Deacon <willdeacon@google.com>, Andrea Parri <parri.andrea@gmail.com>,
 Alan Stern <stern@rowland.harvard.edu>
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <20191014101938.GB41626@lakrids.cambridge.arm.com>
From: Mukesh Ojha <mojha@codeaurora.org>
Message-ID: <0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-000000@us-west-2.amazonses.com>
Date: Thu, 12 Dec 2019 16:22:31 +0000
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191014101938.GB41626@lakrids.cambridge.arm.com>
Content-Type: multipart/alternative;
 boundary="------------95B484F71E19BF8011B47BB4"
Content-Language: en-US
X-SES-Outgoing: 2019.12.12-54.240.27.185
Feedback-ID: 1.us-west-2.CZuq2qbDmUIuT3qdvXlRHZZCpfZqZ4GtG9v3VKgRyF0=:AmazonSES
X-Original-Sender: mojha@codeaurora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codeaurora.org header.s=zsmsymrwgfyinv5wlfyidntwsjeeldzt
 header.b=SVd1N9l0;       dkim=pass header.i=@amazonses.com
 header.s=gdwg2y3kokkkj5a55z2ilkup5wp5hhxx header.b=F7kI2CPL;       spf=pass
 (google.com: domain of 0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-000000@us-west-2.amazonses.com
 designates 54.240.27.185 as permitted sender) smtp.mailfrom=0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-000000@us-west-2.amazonses.com
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
--------------95B484F71E19BF8011B47BB4
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable


On 10/14/2019 3:49 PM, Mark Rutland wrote:
> On Mon, Oct 14, 2019 at 11:09:40AM +0200, Marco Elver wrote:
>> On Mon, 14 Oct 2019 at 10:40, Dmitry Vyukov <dvyukov@google.com> wrote:
>>> On Mon, Oct 14, 2019 at 7:11 AM <sgrover@codeaurora.org> wrote:
>>>> Hi Dmitry,
>>>>
>>>> I am from Qualcomm Linux Security Team, just going through KCSAN
>>>> and found that there was a thread for arm64 support
>>>> (https://lkml.org/lkml/2019/9/20/804).
>>>>
>>>> Can you please tell me if KCSAN is supported on ARM64 now? Can I
>>>> just rebase the KCSAN branch on top of our let=E2=80=99s say android
>>>> mainline kernel, enable the config and run syzkaller on that for
>>>> finding race conditions?
>>>>
>>>> It would be very helpful if you reply, we want to setup this for
>>>> finding issues on our proprietary modules that are not part of
>>>> kernel mainline.
>>>>
>>>> Regards,
>>>>
>>>> Sachin Grover
>>> +more people re KCSAN on ARM64
>> KCSAN does not yet have ARM64 support. Once it's upstream, I would
>> expect that Mark's patches (from repo linked in LKML thread) will just
>> cleanly apply to enable ARM64 support.
> Once the core kcsan bits are ready, I'll rebase the arm64 patch atop.
> I'm expecting some things to change as part of review, so it'd be great
> to see that posted ASAP.
>
> For arm64 I'm not expecting major changes (other than those necessary to
> handle the arm64 atomic rework that went in to v5.4-rc1)

Hi Mark,

Are the below patches enough for kcsan to be working on arm64 ?
I am not sure about the one you are mentioning about "atomic rework=20
patches which went in 5.4 rc1" .

Thanks.
Mukesh

2019-10-03 	arm64, kcsan: enable KCSAN for arm64=20
<https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=
=3Darm64/kcsan&id=3Dae1d089527027ce710e464105a73eb0db27d7875>arm64/kcsan=20
<https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=3Dar=
m64/kcsan>=20
	Mark Rutland 	5 	-1/+5

=09
=09
=09
=09
2019-09-24 	locking/atomics, kcsan: Add KCSAN instrumentation=20
<https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=
=3Darm64/kcsan&id=3D8b3b76ec443b9af7e55994a163bb6f4aee016f09>=20
	Marco Elver 	2 	-2/+199
2019-09-24 	asm-generic, kcsan: Add KCSAN instrumentation for bitops=20
<https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=
=3Darm64/kcsan&id=3D50c23ad00c040927e71c8943d4eb7d52e9f77762>=20
	Marco Elver 	1 	-0/+18
2019-09-24 	seqlock, kcsan: Add annotations for KCSAN=20
<https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=
=3Darm64/kcsan&id=3De2b32e1a3b397bffcb6afbe86f6fe55e2040a34a>=20
	Marco Elver 	1 	-5/+42
2019-09-24 	build, kcsan: Add KCSAN build exceptions=20
<https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=
=3Darm64/kcsan&id=3D35a907033244099a71f17d28e9ffaca92f714463>=20
	Marco Elver 	3 	-0/+17
2019-09-24 	objtool, kcsan: Add KCSAN runtime functions to whitelist=20
<https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=
=3Darm64/kcsan&id=3D3afc592ca7ebd9c13c939c98b995763345e85e08>=20
	Marco Elver 	1 	-0/+17
2019-09-24 	kcsan: Add Kernel Concurrency Sanitizer infrastructure=20
<https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=
=3Darm64/kcsan&id=3D73d893b441dc3e5c1645884a19b46a1bfd4fd692>=20
	Marco Elver



>
> FWIW, I was able to run Syzkaller atop of my arm64/kcsan branch, but
> it's very noisy as it has none of the core fixes.
>
> Thanks,
> Mark.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-000000%40us=
-west-2.amazonses.com.

--------------95B484F71E19BF8011B47BB4
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-8=
">
  </head>
  <body text=3D"#000000" bgcolor=3D"#FFFFFF">
    <p><br>
    </p>
    <div class=3D"moz-cite-prefix">On 10/14/2019 3:49 PM, Mark Rutland
      wrote:<br>
    </div>
    <blockquote type=3D"cite"
      cite=3D"mid:20191014101938.GB41626@lakrids.cambridge.arm.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">On Mon, Oct 14, 2019 at 11:09:=
40AM +0200, Marco Elver wrote:
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">On Mon, 14 Oct 2019 at 10:40=
, Dmitry Vyukov <a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:dvyukov@g=
oogle.com">&lt;dvyukov@google.com&gt;</a> wrote:
</pre>
        <blockquote type=3D"cite">
          <pre class=3D"moz-quote-pre" wrap=3D"">
On Mon, Oct 14, 2019 at 7:11 AM <a class=3D"moz-txt-link-rfc2396E" href=3D"=
mailto:sgrover@codeaurora.org">&lt;sgrover@codeaurora.org&gt;</a> wrote:
</pre>
          <blockquote type=3D"cite">
            <pre class=3D"moz-quote-pre" wrap=3D"">
Hi Dmitry,

I am from Qualcomm Linux Security Team, just going through KCSAN
and found that there was a thread for arm64 support
(<a class=3D"moz-txt-link-freetext" href=3D"https://lkml.org/lkml/2019/9/20=
/804">https://lkml.org/lkml/2019/9/20/804</a>).

Can you please tell me if KCSAN is supported on ARM64 now? Can I
just rebase the KCSAN branch on top of our let=E2=80=99s say android
mainline kernel, enable the config and run syzkaller on that for
finding race conditions?

It would be very helpful if you reply, we want to setup this for
finding issues on our proprietary modules that are not part of
kernel mainline.

Regards,

Sachin Grover
</pre>
          </blockquote>
          <pre class=3D"moz-quote-pre" wrap=3D"">
+more people re KCSAN on ARM64
</pre>
        </blockquote>
        <pre class=3D"moz-quote-pre" wrap=3D"">
KCSAN does not yet have ARM64 support. Once it's upstream, I would
expect that Mark's patches (from repo linked in LKML thread) will just
cleanly apply to enable ARM64 support.
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
Once the core kcsan bits are ready, I'll rebase the arm64 patch atop.
I'm expecting some things to change as part of review, so it'd be great
to see that posted ASAP.

For arm64 I'm not expecting major changes (other than those necessary to
handle the arm64 atomic rework that went in to v5.4-rc1)
</pre>
    </blockquote>
    <p>Hi Mark,<br>
      <br>
    </p>
    <p>Are the below patches enough for kcsan to be working on arm64 ?<br>
      I am not sure about the one you are mentioning about "atomic
      rework patches which went in 5.4 rc1" .<br>
    </p>
    <p>Thanks.<br>
      Mukesh<br>
      <br>
    </p>
    <table class=3D"list nowrap" style=3D"border-collapse: collapse; width:
      1521px; border: none; color: rgb(51, 51, 51); font-family:
      sans-serif; font-size: 13.3333px; font-style: normal;
      font-variant-ligatures: normal; font-variant-caps: normal;
      font-weight: 400; letter-spacing: normal; orphans: 2; text-align:
      start; text-indent: 0px; text-transform: none; white-space:
      normal; widows: 2; word-spacing: 0px; -webkit-text-stroke-width:
      0px; background-color: rgb(255, 255, 255); text-decoration-style:
      initial; text-decoration-color: initial;">
      <tbody>
        <tr style=3D"background: rgb(238, 238, 238);">
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span title=3D"2019-10-03 16:14:35 +0100">2019-10-03</=
span></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><a
href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/comm=
it/?h=3Darm64/kcsan&amp;id=3Dae1d089527027ce710e464105a73eb0db27d7875"
              style=3D"color: black; text-decoration: none;">arm64, kcsan:
              enable KCSAN for arm64</a><span class=3D"decoration"><a
                class=3D"branch-deco"
href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/=
?h=3Darm64/kcsan"
                style=3D"color: black; text-decoration: none; margin: 0px
                0.5em; padding: 0px 0.25em; background-color: rgb(136,
                255, 136); border: 1px solid rgb(0, 119, 0);">arm64/kcsan</=
a></span></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"libravatar"><img class=3D"inline"
src=3D"https://seccdn.libravatar.org/avatar/546ba522be956ba117d48cbbafcc530=
9?s=3D13&amp;d=3Dretro"
                style=3D"border: none; border-radius: 3px; width: 13px;
                height: 13px; margin-right: 0.2em; opacity: 0.4;"></span>Ma=
rk
            Rutland</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;">5</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"deletions" style=3D"color: rgb(136, 0,
              0);">-1</span>/<span class=3D"insertions" style=3D"color:
              rgb(0, 136, 0);">+5</span></td>
        </tr>
        <tr style=3D"background: white;">
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><br>
          </td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><br>
          </td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><br>
          </td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><br>
          </td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><br>
          </td>
        </tr>
        <tr style=3D"background: rgb(247, 247, 247);">
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span title=3D"2019-09-24 17:54:32 +0200">2019-09-24</=
span></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><a
href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/comm=
it/?h=3Darm64/kcsan&amp;id=3D8b3b76ec443b9af7e55994a163bb6f4aee016f09"
              style=3D"color: black; text-decoration: none;">locking/atomic=
s,
              kcsan: Add KCSAN instrumentation</a></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"libravatar"><img class=3D"inline"
src=3D"https://seccdn.libravatar.org/avatar/ade606cb28976e5f1b070eccf7793e0=
b?s=3D13&amp;d=3Dretro"
                style=3D"border: none; border-radius: 3px; width: 13px;
                height: 13px; margin-right: 0.2em; opacity: 0.4;"></span>Ma=
rco
            Elver</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;">2</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"deletions" style=3D"color: rgb(136, 0,
              0);">-2</span>/<span class=3D"insertions" style=3D"color:
              rgb(0, 136, 0);">+199</span></td>
        </tr>
        <tr style=3D"background: white;">
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span title=3D"2019-09-24 17:54:32 +0200">2019-09-24</=
span></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><a
href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/comm=
it/?h=3Darm64/kcsan&amp;id=3D50c23ad00c040927e71c8943d4eb7d52e9f77762"
              style=3D"color: black; text-decoration: none;">asm-generic,
              kcsan: Add KCSAN instrumentation for bitops</a></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"libravatar"><img class=3D"inline"
src=3D"https://seccdn.libravatar.org/avatar/ade606cb28976e5f1b070eccf7793e0=
b?s=3D13&amp;d=3Dretro"
                style=3D"border: none; border-radius: 3px; width: 13px;
                height: 13px; margin-right: 0.2em; opacity: 0.4;"></span>Ma=
rco
            Elver</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;">1</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"deletions" style=3D"color: rgb(136, 0,
              0);">-0</span>/<span class=3D"insertions" style=3D"color:
              rgb(0, 136, 0);">+18</span></td>
        </tr>
        <tr style=3D"background: rgb(247, 247, 247);">
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span title=3D"2019-09-24 17:54:32 +0200">2019-09-24</=
span></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><a
href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/comm=
it/?h=3Darm64/kcsan&amp;id=3De2b32e1a3b397bffcb6afbe86f6fe55e2040a34a"
              style=3D"color: black; text-decoration: none;">seqlock,
              kcsan: Add annotations for KCSAN</a></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"libravatar"><img class=3D"inline"
src=3D"https://seccdn.libravatar.org/avatar/ade606cb28976e5f1b070eccf7793e0=
b?s=3D13&amp;d=3Dretro"
                style=3D"border: none; border-radius: 3px; width: 13px;
                height: 13px; margin-right: 0.2em; opacity: 0.4;"></span>Ma=
rco
            Elver</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;">1</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"deletions" style=3D"color: rgb(136, 0,
              0);">-5</span>/<span class=3D"insertions" style=3D"color:
              rgb(0, 136, 0);">+42</span></td>
        </tr>
        <tr style=3D"background: white;">
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span title=3D"2019-09-24 17:54:32 +0200">2019-09-24</=
span></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><a
href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/comm=
it/?h=3Darm64/kcsan&amp;id=3D35a907033244099a71f17d28e9ffaca92f714463"
              style=3D"color: black; text-decoration: none;">build, kcsan:
              Add KCSAN build exceptions</a></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"libravatar"><img class=3D"inline"
src=3D"https://seccdn.libravatar.org/avatar/ade606cb28976e5f1b070eccf7793e0=
b?s=3D13&amp;d=3Dretro"
                style=3D"border: none; border-radius: 3px; width: 13px;
                height: 13px; margin-right: 0.2em; opacity: 0.4;"></span>Ma=
rco
            Elver</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;">3</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"deletions" style=3D"color: rgb(136, 0,
              0);">-0</span>/<span class=3D"insertions" style=3D"color:
              rgb(0, 136, 0);">+17</span></td>
        </tr>
        <tr style=3D"background: rgb(247, 247, 247);">
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span title=3D"2019-09-24 17:54:32 +0200">2019-09-24</=
span></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><a
href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/comm=
it/?h=3Darm64/kcsan&amp;id=3D3afc592ca7ebd9c13c939c98b995763345e85e08"
              style=3D"color: black; text-decoration: none;">objtool,
              kcsan: Add KCSAN runtime functions to whitelist</a></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"libravatar"><img class=3D"inline"
src=3D"https://seccdn.libravatar.org/avatar/ade606cb28976e5f1b070eccf7793e0=
b?s=3D13&amp;d=3Dretro"
                style=3D"border: none; border-radius: 3px; width: 13px;
                height: 13px; margin-right: 0.2em; opacity: 0.4;"></span>Ma=
rco
            Elver</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;">1</td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"deletions" style=3D"color: rgb(136, 0,
              0);">-0</span>/<span class=3D"insertions" style=3D"color:
              rgb(0, 136, 0);">+17</span></td>
        </tr>
        <tr style=3D"background: white;">
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span title=3D"2019-09-24 17:54:32 +0200">2019-09-24</=
span></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><a
href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/comm=
it/?h=3Darm64/kcsan&amp;id=3D73d893b441dc3e5c1645884a19b46a1bfd4fd692"
              style=3D"color: black; text-decoration: none;">kcsan: Add
              Kernel Concurrency Sanitizer infrastructure</a></td>
          <td style=3D"border: none; padding: 0.1em 0.5em; white-space:
            nowrap;"><span class=3D"libravatar"><img class=3D"inline"
src=3D"https://seccdn.libravatar.org/avatar/ade606cb28976e5f1b070eccf7793e0=
b?s=3D13&amp;d=3Dretro"
                style=3D"border: none; border-radius: 3px; width: 13px;
                height: 13px; margin-right: 0.2em; opacity: 0.4;"></span>Ma=
rco
            Elver</td>
        </tr>
      </tbody>
    </table>
    <p><br>
    </p>
    <p><br>
    </p>
    <blockquote type=3D"cite"
      cite=3D"mid:20191014101938.GB41626@lakrids.cambridge.arm.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">

FWIW, I was able to run Syzkaller atop of my arm64/kcsan branch, but
it's very noisy as it has none of the core fixes.

Thanks,
Mark.
</pre>
    </blockquote>
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
om/d/msgid/kasan-dev/0101016efaeb3fa5-ae09e093-1dce-4ae2-ac73-7ca3fbafb660-=
000000%40us-west-2.amazonses.com?utm_medium=3Demail&utm_source=3Dfooter">ht=
tps://groups.google.com/d/msgid/kasan-dev/0101016efaeb3fa5-ae09e093-1dce-4a=
e2-ac73-7ca3fbafb660-000000%40us-west-2.amazonses.com</a>.<br />

--------------95B484F71E19BF8011B47BB4--
