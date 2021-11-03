Return-Path: <kasan-dev+bncBDKPVCUS7YEBBEORROGAMGQEE62QH6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D7E344492E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Nov 2021 20:52:51 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id d8-20020a253608000000b005c202405f52sf5526800yba.7
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Nov 2021 12:52:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635969170; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ukre4LpWSshljQGb/ZNHlLsaedIXlQiBIzdIRzRSTgN47Ihc1eGxsbDjlhIKLGSQei
         UXyEJ1Q7e6sGV0m5gWLNhDHTPHVpkxOJiYa3VJmiio+z9uH+VV8qQ/u37tob5CB/HVwD
         2ehnI3uHAzAVmo9hbnqGF5LmYlNMFnh5dtm7Z29auDbejnIWEUsGEF0nxMZFBnZzJcm5
         1UUvZt/AovJYhjWkyqFSvBkTXvR6IMGXgzJMc/TJVNRF2adCKXgx8vhhPsztL5xCvgT0
         HYhBg17VrZLGOXBgJ34f+rhTZoqkjx0saTeeOkNufRgp3pF91Ursn8GBVhBXxGiH+DDa
         1IHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=kEXl2kE65SIqT6SUAwpDz9E0V2guew9nYRtXpkKqqqk=;
        b=QNspUDhXV/R5tIP60YD+P9+K7K6scmSvYsmvKzSr/6OjkEsyADZY19/yiBeX08rG1L
         RNugcidSaWUfOyrn8/xhgUElco+kXAiMsM+w3iuweFbso2s/9f+N5qFzSraE9A5RNQ6p
         d0xPyK9CnvzN0tUePa0Xa7mt6372PTBc7ZhMq0AU6RNAJSk5y4JMWXDLTfj7tL6pM7li
         pNf1GWddftSjad49QddzYUkrlaEU11T5F+Pc2FPZZciGO/xinxRN4hGfilGrazvua01D
         H2kI+wJjDSm7jChbBVYOHfDHTklygkcC/tHw6nE2/YVPo0Hi/ziSeNd9TIdbrR1ES02d
         D/iQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WB7B4bBy;
       spf=pass (google.com: domain of dankonate02@gmail.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=dankonate02@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kEXl2kE65SIqT6SUAwpDz9E0V2guew9nYRtXpkKqqqk=;
        b=r0+r9lAjiiTvd53odXGT5SIg46BK8e+g4Avrm7GgxRV1zjZqKtSlLZciSqgYdkw4+8
         4xycE1qjaALQZrtPtki9DloA9xSBZk/v3xPYDDFs2ZlEhm6TbUJdA8I9bc2C3CUlrP6v
         7b13s1ISWNWmYN3vI2pQ1+E+R1TDQYxU51MEYY/CRMuUF+z9lg95JmigUyqxWJaaHSjY
         2NngrSwWc7Kt7LzKmER5wyCLMLdvGETyB7XUKXJD/3xJeqAjOIEM7x4+b2S+x9cR07h8
         kt5NRinvPbwrq7WkJLkqz7ry6f7j7Jj8j6eJHB1MpVUVU9VcGCCW8W7dSPYTxAeHTAnm
         AEhw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kEXl2kE65SIqT6SUAwpDz9E0V2guew9nYRtXpkKqqqk=;
        b=f7oWYQ8a4i9vNgPTNiRewZ56QWW/ICTU1bY5J9BPSDfdF9rGBRJTemm3g62a/CLrOH
         wCGzWIRWUQsvARgD3lg9PzO/sZHTbwfIREqZpkzHPdWqY6IPU5Khq0ONVNS3Ga4rxZhS
         rISYflihxNmvuLOyqmGTltRown5w6QQCibYRK9GZGTZG+pmYYwekG75UdKa9AO8eYwxX
         00UNmyKzt/6KrkNZt9dLLlp1APn6MhuBAaFau1oUzgqFA/oFa2viW8zE0EKWarcRN3Lw
         1CIZRsIGv28gMII4rxJ9TWpujF8ZUeBLWnabFTN10kdOfQc8Ugd2nJynjy8j26JDFONn
         9hag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=kEXl2kE65SIqT6SUAwpDz9E0V2guew9nYRtXpkKqqqk=;
        b=x9lpXaPvot/jbEOzTZeYxALX4uWlAtl5t7FNlcTynspqh7a85aYoDg7FO4tGDhMvjS
         r5DOi6KI2pC6IgX2wB4+YG5hX233IuZyPCGCVR/1fB19EXSF5wzvZiaY4g9lw9B5AN+X
         hhKZVGKJHPtOT4Wg3cVBT119X2Re2Z2ZXQvChjd8bJztyWXmCOlRI8zYc9FSuOh+HrLd
         MoWgGg5W4xCBNzOB2fldt+3537koenVKJOWgH0mBCStjbKakViRIoDUc7SB7VSX34FmJ
         cC8BedH527P0gVj/tUqZVmwKPyWJxFrknrFsC3+P1jz+BufFILfazdF+6Hwap0Otvj1K
         i6yA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336NUJlo4bPKqc7TaTslUT4c7P0E6MMijZPVZfBRos4T1gSGuwj
	p4QKxWJjKogobIYUbpZ1ezg=
X-Google-Smtp-Source: ABdhPJy3WBE6v1T3nBsZHhMkuHPM+ST0BBWkmYGLWc0yZzPFQEjraK8pGDNIGgZ/p2DxD5zuyMg2bg==
X-Received: by 2002:a25:d655:: with SMTP id n82mr9287023ybg.451.1635969169914;
        Wed, 03 Nov 2021 12:52:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:25d0:: with SMTP id l199ls2306283ybl.6.gmail; Wed, 03
 Nov 2021 12:52:49 -0700 (PDT)
X-Received: by 2002:a5b:98e:: with SMTP id c14mr31547462ybq.458.1635969169449;
        Wed, 03 Nov 2021 12:52:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635969169; cv=none;
        d=google.com; s=arc-20160816;
        b=1Jglop3I5Za+pZFHFy4XSuIdHRBw1xeaJq1/SCIFDWbWAigeM82yNGB3KqvbTMP0ME
         NWeQGXxGxkeGasM0ZW9p7ZBrRqV/xz/ohqmVO6OriFeJv+yoj4AoKCrBcQsH8+MS1/Fe
         Z1jl6myWaQHsGPBNK+Z8wLtetVUkoZudz8g+qolSNe+iQgucQ8HIAbNICqFUSlYlPO/A
         /9zuV7B7QrwOYWdXua0HobWy4YuIGzUoWB5Hmuvi1r9AqRUYACTUtz7zVzjmL/33HA/H
         KBrdlnfZaLJHUDIOtaUsyMyHuC2dKOw5SDsvibCLwGYWQKIVlAfpZOvrSlZtybURZ86l
         LDjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=eHrXUesB1ATELMrrxaLWxAXjLwKWC9ZMf6RIrHXWCB8=;
        b=c9L6dNPL2ULpbiaMHX5wo5M0X39ayIXdvuiPAKC17AevoS1Quieo7AEEl6nDngJZVl
         tX26Nmu/4aiNsHEIau1n+my1ttUBG3QqJJaKTTLq94GK7JVklnGwq8PbG78/byMytFUn
         ky1myCHgBJffAdiZtipPU1mBwmCGcwQvi4wHfUeeQrBHff+QC9wU2CLyX9RvDLiPHIct
         zci+Zbd2TOyBr4BxCr4DqrcXETfSMja8FmXBNueZh8h64RFDu9gT9gs00asVwlxpwM0I
         V6wBE9UiSxdTosERn3mJ3/hD7rS2HbIvw54T3WMHQSJ/a3+d5ajmJMdpN6JAH2EHt4x0
         dWaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WB7B4bBy;
       spf=pass (google.com: domain of dankonate02@gmail.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=dankonate02@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id w5si19983ybe.0.2021.11.03.12.52.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Nov 2021 12:52:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dankonate02@gmail.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id az37so6517631uab.13
        for <kasan-dev@googlegroups.com>; Wed, 03 Nov 2021 12:52:49 -0700 (PDT)
X-Received: by 2002:a67:f518:: with SMTP id u24mr31564854vsn.6.1635969169063;
 Wed, 03 Nov 2021 12:52:49 -0700 (PDT)
MIME-Version: 1.0
From: Joel Daniel <djoel2533@gmail.com>
Date: Wed, 3 Nov 2021 19:52:34 +0000
Message-ID: <CAEf51ReJCs+nYMnvNZdxyDzcUEA=n-+SFL3PuPOKqxxcVk00wg@mail.gmail.com>
Subject: Can I confide in you?
To: djoel2533@gmail.com
Content-Type: multipart/alternative; boundary="0000000000002f83c705cfe7c1e4"
X-Original-Sender: djoel2533@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=WB7B4bBy;       spf=pass
 (google.com: domain of dankonate02@gmail.com designates 2607:f8b0:4864:20::930
 as permitted sender) smtp.mailfrom=dankonate02@gmail.com;       dmarc=pass
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

--0000000000002f83c705cfe7c1e4
Content-Type: text/plain; charset="UTF-8"

 Can I confide in you?

I have a very important and confidential business proposal that I would
love to transact with you if only I can confide in you
Let me know so that I can give you the full details of this important
proposal

Regards
Mr. Joel Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAEf51ReJCs%2BnYMnvNZdxyDzcUEA%3Dn-%2BSFL3PuPOKqxxcVk00wg%40mail.gmail.com.

--0000000000002f83c705cfe7c1e4
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">

<div style=3D"color:rgb(34,34,34);font-family:Arial,Helvetica,sans-serif;fo=
nt-size:small;font-style:normal;font-variant-ligatures:normal;font-variant-=
caps:normal;font-weight:400;letter-spacing:normal;text-align:start;text-ind=
ent:0px;text-transform:none;white-space:normal;word-spacing:0px;text-decora=
tion-style:initial;text-decoration-color:initial">Can I confide in you?</di=
v><div style=3D"color:rgb(34,34,34);font-family:Arial,Helvetica,sans-serif;=
font-size:small;font-style:normal;font-variant-ligatures:normal;font-varian=
t-caps:normal;font-weight:400;letter-spacing:normal;text-align:start;text-i=
ndent:0px;text-transform:none;white-space:normal;word-spacing:0px;text-deco=
ration-style:initial;text-decoration-color:initial">=C2=A0</div><div style=
=3D"color:rgb(34,34,34);font-family:Arial,Helvetica,sans-serif;font-size:sm=
all;font-style:normal;font-variant-ligatures:normal;font-variant-caps:norma=
l;font-weight:400;letter-spacing:normal;text-align:start;text-indent:0px;te=
xt-transform:none;white-space:normal;word-spacing:0px;text-decoration-style=
:initial;text-decoration-color:initial">I have a very important and confide=
ntial business proposal that I would love to transact with you if only I ca=
n confide in you<br>Let me know so that I can give you the full details of =
this important proposal=C2=A0</div><div style=3D"color:rgb(34,34,34);font-f=
amily:Arial,Helvetica,sans-serif;font-size:small;font-style:normal;font-var=
iant-ligatures:normal;font-variant-caps:normal;font-weight:400;letter-spaci=
ng:normal;text-align:start;text-indent:0px;text-transform:none;white-space:=
normal;word-spacing:0px;text-decoration-style:initial;text-decoration-color=
:initial">=C2=A0</div><div style=3D"color:rgb(34,34,34);font-family:Arial,H=
elvetica,sans-serif;font-size:small;font-style:normal;font-variant-ligature=
s:normal;font-variant-caps:normal;font-weight:400;letter-spacing:normal;tex=
t-align:start;text-indent:0px;text-transform:none;white-space:normal;word-s=
pacing:0px;text-decoration-style:initial;text-decoration-color:initial">Reg=
ards<br>Mr. Joel Daniel</div>

</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAEf51ReJCs%2BnYMnvNZdxyDzcUEA%3Dn-%2BSFL3PuPOKqxxcVk0=
0wg%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CAEf51ReJCs%2BnYMnvNZdxyDzcUEA%3Dn-%2BSFL3PuP=
OKqxxcVk00wg%40mail.gmail.com</a>.<br />

--0000000000002f83c705cfe7c1e4--
