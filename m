Return-Path: <kasan-dev+bncBCH2XPOBSAERBZ6T5T6QKGQEOQPJHMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 588F22BFE8E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 04:18:01 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id b11sf4373644oon.14
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Nov 2020 19:18:01 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KQvZPLoynEQM1ptXLajraqjNgLrkPZexnuxQLTwrzwo=;
        b=BpFCF4UVux+4OfX+2AjxRAakXVP+vh6oC2qTIE7xeQRGUHvJaFbz3e4LYQlTqDY5yM
         5B75seFNEj8KXcmmm+Cidsb9OhLEEXljRxhGadub16tvVxFup5ApRAdJk08TXGRbnY1b
         KQZxq/iDTRo+1SdPq3paEHnnVQ3RVyAg4p7UdV9jrgrMJKpJ/bdKWCujXNc9iexkTzHe
         ej77/+AlNUwStaY/1BooYAdolhK4c8b3oUxwRz34Z2otMPdwo5UsQ8CWFjdrOksePH38
         f8kNGlSTFv4Vglr2jAce5Lm6+Xt3ceBFfJMTTs8jzNQ8WYrGCNPNjUsrf6d1EVfgGvXC
         Nnbw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KQvZPLoynEQM1ptXLajraqjNgLrkPZexnuxQLTwrzwo=;
        b=DL0BoMqZple2Bvd2EoHIeusaD/CryE33pqyn/8k1BtyiW98SIjpdCEewsL3PnXJGme
         CHpqGvoVaAGgOwvkYGKHVNHRl+2kcZ65f1Cu2xpY5UGvKHLE8NS5u1Nhn0ETXfewXzKb
         nMI8uW/wFFk4iHPdPoPASS6vSjmF9cAuSERbVuiNk4YXXFDk8c2rte2xNx9rf147Ptet
         Zm/KXtqzqdJLUVfwWlZAacCyIJBH8fClh0oXZTQjY5yduXkDSlWHlKZ8kTRmeHoSDGJ9
         DnXJMztTxXruChZ6f/vRnFq7ZKp1Y2Un/s21SraERffXMVpknIpb4VmR2Qy2C3qndAeI
         HdzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KQvZPLoynEQM1ptXLajraqjNgLrkPZexnuxQLTwrzwo=;
        b=rZOkdR7Ht1rgaTzzVkg5Aa/ANtzaqfpsMi/Qd5j8mKY9x/VSRBmDFC1lCJt+4I6LQa
         ufApTM2IP8e1CF816o1NzrIP2dgCsSN8iVG3VBQIrN7QmZwTOlEkpjSlI3bq534jUIbZ
         0j+ULxCGbbUiRE8YU2mkpD6WnE99fYkhyMgXh2UnIahbtF+u6t2GUMZ/ryxbLL0iww/H
         o3vZkQB8Dn0DPEh6sgUBAb/PAeSb5lkFWRK+XeNAsvRYZpLgxVU5s3LbMzsEAaEqLpvT
         DuBkTQFoG7xv3QS3yJzNie0GzODgGFZxYmaUfbFDpRjPhHY3UppLby3e0ucBpbiULV45
         yoPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PnStoZhuUyPpELlIXYg994syLinDW2uSxrogc5pYLr7i19lGp
	4HVWHvGR2avN0D0WXi4m21c=
X-Google-Smtp-Source: ABdhPJztItk5RC7lYoSlM9yCKfIePIngwkyDcfE8JzxqAnfORi5ah11qifpYBXJIUAEVGGA5GWi9yg==
X-Received: by 2002:a54:4704:: with SMTP id k4mr14212030oik.39.1606101479901;
        Sun, 22 Nov 2020 19:17:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1f59:: with SMTP id u25ls3060508oth.1.gmail; Sun,
 22 Nov 2020 19:17:59 -0800 (PST)
X-Received: by 2002:a9d:32b6:: with SMTP id u51mr22168245otb.119.1606101479332;
        Sun, 22 Nov 2020 19:17:59 -0800 (PST)
Date: Sun, 22 Nov 2020 19:17:58 -0800 (PST)
From: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <8b89f21f-e3e9-4344-92d3-580d2f0f2860n@googlegroups.com>
In-Reply-To: <CANpmjNPsjXqDQLkeBb2Ap7j8rbrDwRHeuGPyzXXQ++Qxe4A=7A@mail.gmail.com>
References: <f4a62280-43f5-468b-94c4-fdda826d28d0n@googlegroups.com>
 <CANpmjNPsjXqDQLkeBb2Ap7j8rbrDwRHeuGPyzXXQ++Qxe4A=7A@mail.gmail.com>
Subject: Re: Any guidance to port KCSAN to previous Linux Kernel versions?
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_4536_249421192.1606101478561"
X-Original-Sender: mudongliangabcd@gmail.com
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

------=_Part_4536_249421192.1606101478561
Content-Type: multipart/alternative; 
	boundary="----=_Part_4537_913861416.1606101478562"

------=_Part_4537_913861416.1606101478562
Content-Type: text/plain; charset="UTF-8"



On Wednesday, November 18, 2020 at 6:05:45 PM UTC+8 el...@google.com wrote:

> On Wed, 18 Nov 2020 at 08:09, mudongl...@gmail.com 
> <mudongl...@gmail.com> wrote: 
> > 
> > Hello all, 
> > 
> > I am writing to ask for some guidance to port KCSAN to some LTS kernel 
> versions. As KCSAN is already merged into upstream and works well to catch 
> some bugs in some kernel trees, it is good idea to port KCSAN to some 
> previous Linux Kernel version. On one hand, it is good for bug detection in 
> LTS kernel; On the other hand, it is good to diagnose some kernel crashes 
> caused by data race. 
> > 
> > Thanks in advance. 
> > 
> > Dongliang Mu 
>
> There have been major changes to READ_ONCE()/WRITE_ONCE() in Linux 5.8 
> which make backporting non-trivial since those changes would have to 
> be backported, too. Your best bet might be looking at the version of 
> KCSAN at 50a19ad4b1ec: git log v5.7-rc7..50a19ad4b1ec -- but that is 
> missing some important changes, and I question the value in 
> backporting. 
>

Thanks for your explanation. That's helpful.

Let's imagine a scenario: KASAN detects a UAF crash in an old Linux 
kernel(e.g., 5.4, 4.19), but the underlying reason for this crash behavior 
is data racing from two different threads with plain accesses(without 
READ_ONCE/WRITE_ONCE).
What I want is to backport KCSAN and test whether it could catch the 
underlying data race before triggering the further UAF crash. This would 
help us identify the underlying issue(two concurrent threads and the object 
for data race) and fix the bug completely.

Therefore, if I try to backport KCSAN and test whether KCSAN catches this 
special data race, is it still too complicated or need non-trivial efforts?


> In particular, we have the following problem: The kernel still has 
> (and before 5.5 it was worse) numerous very frequent data races that 
> are -- with current compilers and architectures -- seemingly benign, 
> or failure due to them is unlikely. The emphasis here should be on 
> _very frequent data races_, because we know there are infrequent data 
> races that are potentially harmful. But, unfortunately we're still 
> suffering from a "find the needle in the haystack problem" here. Which 
> means a backport isn't going to be too helpful right now because we'd 
> only like to tackle this problem for mainline right now. A better 
> approach is to backport fixes as required. 
>
> We are slowly working on addressing these problems, the most 
> straightforward approach would be to mark intentional data races and 
> fix other issues, but that isn't trivial because there are so many and 
> each needs to be carefully analyzed. 
>
> I recommend reading https://lwn.net/Articles/816854/ . 
>
> Thanks, 
> -- Marco 
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8b89f21f-e3e9-4344-92d3-580d2f0f2860n%40googlegroups.com.

------=_Part_4537_913861416.1606101478562
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<br><br><div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">O=
n Wednesday, November 18, 2020 at 6:05:45 PM UTC+8 el...@google.com wrote:<=
br></div><blockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; bo=
rder-left: 1px solid rgb(204, 204, 204); padding-left: 1ex;">On Wed, 18 Nov=
 2020 at 08:09, <a href=3D"" data-email-masked=3D"" rel=3D"nofollow">mudong=
l...@gmail.com</a>
<br>&lt;<a href=3D"" data-email-masked=3D"" rel=3D"nofollow">mudongl...@gma=
il.com</a>&gt; wrote:
<br>&gt;
<br>&gt; Hello all,
<br>&gt;
<br>&gt; I am writing to ask for some guidance to port KCSAN to some LTS ke=
rnel versions. As KCSAN is already merged into upstream and works well to c=
atch some bugs in some kernel trees, it is good idea to port KCSAN to some =
previous Linux Kernel version. On one hand, it is good for bug detection in=
 LTS kernel; On the other hand, it is good to diagnose some kernel crashes =
caused by data race.
<br>&gt;
<br>&gt; Thanks in advance.
<br>&gt;
<br>&gt; Dongliang Mu
<br>
<br>There have been major changes to READ_ONCE()/WRITE_ONCE() in Linux 5.8
<br>which make backporting non-trivial since those changes would have to
<br>be backported, too. Your best bet might be looking at the version of
<br>KCSAN at 50a19ad4b1ec: git log v5.7-rc7..50a19ad4b1ec -- but that is
<br>missing some important changes, and I question the value in
<br>backporting.
<br></blockquote><div><br></div><div>Thanks for your explanation. That's he=
lpful.</div><div><br></div><div>Let's imagine a scenario: KASAN detects a U=
AF crash in an old Linux kernel(e.g., 5.4, 4.19), but the underlying reason=
 for this crash behavior is data racing from two different threads with pla=
in accesses(without READ_ONCE/WRITE_ONCE).</div><div>What I want is to back=
port KCSAN and test whether it could catch the underlying data race before =
triggering the further UAF crash. This would help us identify the underlyin=
g issue(two concurrent threads and the object for data race) and fix the bu=
g completely.</div><div><br></div><div>Therefore, if I try to backport KCSA=
N and test whether KCSAN catches this special data race, is it still too co=
mplicated or need non-trivial efforts?<br></div><div><br></div><blockquote =
class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-left: 1px solid =
rgb(204, 204, 204); padding-left: 1ex;">
<br>In particular, we have the following problem: The kernel still has
<br>(and before 5.5 it was worse) numerous very frequent data races that
<br>are -- with current compilers and architectures -- seemingly benign,
<br>or failure due to them is unlikely. The emphasis here should be on
<br>_very frequent data races_, because we know there are infrequent data
<br>races that are potentially harmful. But, unfortunately we're still
<br>suffering from a "find the needle in the haystack problem" here. Which
<br>means a backport isn't going to be too helpful right now because we'd
<br>only like to tackle this problem for mainline right now. A better
<br>approach is to backport fixes as required.
<br>
<br>We are slowly working on addressing these problems, the most
<br>straightforward approach would be to mark intentional data races and
<br>fix other issues, but that isn't trivial because there are so many and
<br>each needs to be carefully analyzed.
<br>
<br>I recommend reading <a href=3D"https://lwn.net/Articles/816854/" target=
=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.google.com=
/url?hl=3Den&amp;q=3Dhttps://lwn.net/Articles/816854/&amp;source=3Dgmail&am=
p;ust=3D1606186125085000&amp;usg=3DAFQjCNGsXFMb3deOitwnx8CpIykoRSOgig">http=
s://lwn.net/Articles/816854/</a> .
<br>
<br>Thanks,
<br>-- Marco
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/8b89f21f-e3e9-4344-92d3-580d2f0f2860n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/8b89f21f-e3e9-4344-92d3-580d2f0f2860n%40googlegroups.com</a>.<b=
r />

------=_Part_4537_913861416.1606101478562--

------=_Part_4536_249421192.1606101478561--
