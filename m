Return-Path: <kasan-dev+bncBCH2XPOBSAERBHPM536QKGQEOZJQU4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 43A842C0865
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 14:16:15 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id i11sf8258797otr.8
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 05:16:15 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qxzld2uTRqRqa2zmShpy1uM8dX2qBBeJNtFpNNpzQ1Q=;
        b=JVVms6VLKhYFIfNRkx3c4NYl+NnrZoSSEP9Ac8t72iHc2Nn/oRA6yM5zg84Tzz+YJO
         5DUh/L9LHK5SwemN1Uev95MHsQFmFPjYoi1CzsI2hw0Cd6ltjK3N2eKB2EoehgZ1b2km
         7bU2qGexxK7TdnuBwh40sYZ/eUFp5hv8+BC8UHldwuh/Lq5Q4s7ZmZjSgyq0tpexwhHM
         ymt1MUjazDsNJ1UAkU1ZUNcSpOhKfTaxLHuCXCDLtqLOIUp4YBygzdpwe3QblJG/oTel
         q9ialnY2iLpyt0nedl1CZXtCsnto//nEK4+J6o7EwavvymJXpp5jiWOJaQ6Ggvx0usqv
         Y9Qw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qxzld2uTRqRqa2zmShpy1uM8dX2qBBeJNtFpNNpzQ1Q=;
        b=rogiC3sgq2MAPeVDi4UBo1mJxcP6877A7C4RYqGGSNkUx0Pqj/m84rmbs29MDXs8yr
         Eh8JUdDjFY55ihG3lO/qQkSbzJGuIM+FzmGljyAx3OqUNTSJOT8mezai4mG+BhgWJRXz
         D9KdnqfwQ2ILrmXp3Gctu2M+N0Go61i6Y4fqHHttzpbklfykM34VDVkgQK6IWVA2Qyxm
         WSYEqYG2uCP/AXvCMMSqKElUd/tVqQKfn5oG3u2DCwM7De3+TxyGM/2eJ3tweII0BxVi
         B1II1Jdh5z/ce+QOY6ojoto4DEL+KTV5rIXR3sxJLFC5Yskjs1tr5DMOlVLo6yxrO9QV
         ECIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qxzld2uTRqRqa2zmShpy1uM8dX2qBBeJNtFpNNpzQ1Q=;
        b=VJoWn2ytK9gXoX6swnIE8WShQVqa5S1gcmmeMET8X7R6fl2ORIrBv2n7P9G7Chjrct
         OsTNdZ6vMcVORWsgdWndDGQaIJ4g9K5E7uYAC5VNlsU8beaGvlnWmNQEHw0kE/wcnAR/
         Q6QYLlCqAEm/bNpZ2ueMieV19sWlmSxQmJb2HxAn2R85gi46sFDYZCIWBo6bcfrO0Sw1
         4+igI4674hPK9fUBRrJxJl9DMgsfW0jDV9Xy0MQKBhiWTlas/uzyuMRwP9k4/d+jwWtH
         TUaD3QRNE8TGMPJufVMfr4yIyWkWwSCl/rKI3LcBGgPKKnRlxLe2G8GXbZT6OkOgFy8j
         SBFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326s0+QA+Ji1TPidNoy7DAPsg6LMhpZaPRpoPRRHDxANUecmciC
	G9jEyDniMGXGKznWsBXShbk=
X-Google-Smtp-Source: ABdhPJyLbxz85iEHgLGhNUVUi+Nj8W1Pja6s06APvMzhqtZGKSqsIN6jAqdJmdIT640CvWZx0oQ3eQ==
X-Received: by 2002:aca:5212:: with SMTP id g18mr13837874oib.145.1606137373932;
        Mon, 23 Nov 2020 05:16:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d658:: with SMTP id y24ls848394oos.7.gmail; Mon, 23 Nov
 2020 05:16:13 -0800 (PST)
X-Received: by 2002:a4a:9e02:: with SMTP id t2mr8560304ook.42.1606137373311;
        Mon, 23 Nov 2020 05:16:13 -0800 (PST)
Date: Mon, 23 Nov 2020 05:16:12 -0800 (PST)
From: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <43db662c-ac04-4ba0-803f-2e7f8c3bdd55n@googlegroups.com>
In-Reply-To: <CANpmjNOWVO1XnPvB9M1HS1Pm_DKOU-yVxANHE0r7JSOX5Xbw7A@mail.gmail.com>
References: <f4a62280-43f5-468b-94c4-fdda826d28d0n@googlegroups.com>
 <CANpmjNPsjXqDQLkeBb2Ap7j8rbrDwRHeuGPyzXXQ++Qxe4A=7A@mail.gmail.com>
 <8b89f21f-e3e9-4344-92d3-580d2f0f2860n@googlegroups.com>
 <CANpmjNPm3U=aeuhv4CpqsxbkQj8SnKbauLmXyAu2b=8bCEg6pQ@mail.gmail.com>
 <83c70bdd-4f74-421a-85bc-fd518f303ce1n@googlegroups.com>
 <CANpmjNOWVO1XnPvB9M1HS1Pm_DKOU-yVxANHE0r7JSOX5Xbw7A@mail.gmail.com>
Subject: Re: Any guidance to port KCSAN to previous Linux Kernel versions?
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_3600_624009885.1606137372517"
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

------=_Part_3600_624009885.1606137372517
Content-Type: multipart/alternative; 
	boundary="----=_Part_3601_2075134254.1606137372517"

------=_Part_3601_2075134254.1606137372517
Content-Type: text/plain; charset="UTF-8"



On Monday, November 23, 2020 at 9:04:22 PM UTC+8 el...@google.com wrote:

> [Resend with reply-all] 
>
> On Mon, 23 Nov 2020 at 13:44, mudongl...@gmail.com 
> <mudongl...@gmail.com> wrote: 
> [...] 
> >> > Let's imagine a scenario: KASAN detects a UAF crash in an old Linux 
> kernel(e.g., 5.4, 4.19), but the underlying reason for this crash behavior 
> is data racing from two different threads with plain accesses(without 
> READ_ONCE/WRITE_ONCE). 
> >> > What I want is to backport KCSAN and test whether it could catch the 
> underlying data race before triggering the further UAF crash. This would 
> help us identify the underlying issue(two concurrent threads and the object 
> for data race) and fix the bug completely. 
> >> 
> >> For debugging such issues, I'd run with a more aggressive KCSAN config 
> >> (regardless of kernel version): 
> >> 
> >> CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=n 
> >> CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n 
> >> 
> >> and lower 'kcsan.skip_watch=' boot parameter from default of 4000 down 
> >> to ~500 in decrements of 500 and stop when the system becomes too 
> >> slow. 
> >> 
> > 
> > That's a good idea. I will try this config when testing my problem. 
> > 
> >> 
> >> > Therefore, if I try to backport KCSAN and test whether KCSAN catches 
> this special data race, is it still too complicated or need non-trivial 
> efforts? 
> >> 
> >> See if 'git cherry-pick v5.7-rc7..50a19ad4b1ec' works. 
> > 
> > 
> > Quick question about the above command: cherry-pick requires the first 
> commit(v5.7-rc7) is older than the second commit(50a19ad4b1ec). However, 
>
> This is incorrect. See "git help log" or [1] -- age is irrelevant. 
> Git's range operators are effectively set operations, and ordering is 
> irrelevant. 
> [1] https://git-scm.com/book/en/v2/Git-Tools-Revision-Selection 
>
> > commit 9cb1fd0efd195590b828b9b865421ad345a4a145 (tag: v5.7-rc7) 
> > Author: Linus Torvalds <torv...@linux-foundation.org> 
> > Date: Sun May 24 15:32:54 2020 -0700 
> > 
> > Linux 5.7-rc7 
> > 
> > commit 50a19ad4b1ec531eb550183cb5d4ab9f25a56bf8 
> > Author: Marco Elver <el...@google.com> 
> > Date: Fri Apr 24 17:47:30 2020 +0200 
> > 
> > objtool, kcsan: Add kcsan_disable_current() and 
> kcsan_enable_current_nowarn() 
> > 
> > Both are safe to be called from uaccess contexts. 
> > 
> > Signed-off-by: Marco Elver <el...@google.com> 
> > Signed-off-by: Paul E. McKenney <pau...@kernel.org> 
> > 
> > However, in fact it does not hold. 
> > 
> > After a search, I found the first commit to add the infrastructure is 
> dfd402a4c4baae42398ce9180ff424d589b8bffc kcsan: Add Kernel Concurrency 
> Sanitizer infrastructure, right after 5.4-rc7. 
> > Do you mean "git cherry-pick v5.4-rc7..50a19ad4b1ec" 
>
> No. 
>
> See "git help log". Specifically "a..b" means "list all the commits 
> which are reachable from b, but not from a". Because we only want 
> KCSAN related commits, the above is correct. Try it! You can also 
> check what commits you'll get by sanity-checking with 'git log'. 
>
>
I see. I am a Git newbie. Thanks for your detailed explanation.
 

> Thanks, 
> -- Marco 
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/43db662c-ac04-4ba0-803f-2e7f8c3bdd55n%40googlegroups.com.

------=_Part_3601_2075134254.1606137372517
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<br><br><div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">O=
n Monday, November 23, 2020 at 9:04:22 PM UTC+8 el...@google.com wrote:<br>=
</div><blockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; borde=
r-left: 1px solid rgb(204, 204, 204); padding-left: 1ex;">[Resend with repl=
y-all]
<br>
<br>On Mon, 23 Nov 2020 at 13:44, <a href=3D"" data-email-masked=3D"" rel=
=3D"nofollow">mudongl...@gmail.com</a>
<br>&lt;<a href=3D"" data-email-masked=3D"" rel=3D"nofollow">mudongl...@gma=
il.com</a>&gt; wrote:
<br>[...]
<br>&gt;&gt; &gt; Let's imagine a scenario: KASAN detects a UAF crash in an=
 old Linux kernel(e.g., 5.4, 4.19), but the underlying reason for this cras=
h behavior is data racing from two different threads with plain accesses(wi=
thout READ_ONCE/WRITE_ONCE).
<br>&gt;&gt; &gt; What I want is to backport KCSAN and test whether it coul=
d catch the underlying data race before triggering the further UAF crash. T=
his would help us identify the underlying issue(two concurrent threads and =
the object for data race) and fix the bug completely.
<br>&gt;&gt;
<br>&gt;&gt; For debugging such issues, I'd run with a more aggressive KCSA=
N config
<br>&gt;&gt; (regardless of kernel version):
<br>&gt;&gt;
<br>&gt;&gt; CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn
<br>&gt;&gt; CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn
<br>&gt;&gt;
<br>&gt;&gt; and lower 'kcsan.skip_watch=3D' boot parameter from default of=
 4000 down
<br>&gt;&gt; to ~500 in decrements of 500 and stop when the system becomes =
too
<br>&gt;&gt; slow.
<br>&gt;&gt;
<br>&gt;
<br>&gt; That's a good idea. I will try this config when testing my problem=
.
<br>&gt;
<br>&gt;&gt;
<br>&gt;&gt; &gt; Therefore, if I try to backport KCSAN and test whether KC=
SAN catches this special data race, is it still too complicated or need non=
-trivial efforts?
<br>&gt;&gt;
<br>&gt;&gt; See if 'git cherry-pick v5.7-rc7..50a19ad4b1ec' works.
<br>&gt;
<br>&gt;
<br>&gt; Quick question about the above command: cherry-pick requires the f=
irst commit(v5.7-rc7) is older than the second commit(50a19ad4b1ec). Howeve=
r,
<br>
<br>This is incorrect. See "git help log" or [1] -- age is irrelevant.
<br>Git's range operators are effectively set operations, and ordering is
<br>irrelevant.
<br>[1] <a href=3D"https://git-scm.com/book/en/v2/Git-Tools-Revision-Select=
ion" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www=
.google.com/url?hl=3Den&amp;q=3Dhttps://git-scm.com/book/en/v2/Git-Tools-Re=
vision-Selection&amp;source=3Dgmail&amp;ust=3D1606223650244000&amp;usg=3DAF=
QjCNGKqsaj1FOgCHQ2Vmgt85gh-y2CDw">https://git-scm.com/book/en/v2/Git-Tools-=
Revision-Selection</a>
<br>
<br>&gt; commit 9cb1fd0efd195590b828b9b865421ad345a4a145 (tag: v5.7-rc7)
<br>&gt; Author: Linus Torvalds &lt;<a href=3D"" data-email-masked=3D"" rel=
=3D"nofollow">torv...@linux-foundation.org</a>&gt;
<br>&gt; Date:   Sun May 24 15:32:54 2020 -0700
<br>&gt;
<br>&gt;     Linux 5.7-rc7
<br>&gt;
<br>&gt; commit 50a19ad4b1ec531eb550183cb5d4ab9f25a56bf8
<br>&gt; Author: Marco Elver &lt;<a href=3D"" data-email-masked=3D"" rel=3D=
"nofollow">el...@google.com</a>&gt;
<br>&gt; Date:   Fri Apr 24 17:47:30 2020 +0200
<br>&gt;
<br>&gt;     objtool, kcsan: Add kcsan_disable_current() and kcsan_enable_c=
urrent_nowarn()
<br>&gt;
<br>&gt;     Both are safe to be called from uaccess contexts.
<br>&gt;
<br>&gt;     Signed-off-by: Marco Elver &lt;<a href=3D"" data-email-masked=
=3D"" rel=3D"nofollow">el...@google.com</a>&gt;
<br>&gt;     Signed-off-by: Paul E. McKenney &lt;<a href=3D"" data-email-ma=
sked=3D"" rel=3D"nofollow">pau...@kernel.org</a>&gt;
<br>&gt;
<br>&gt; However, in fact it does not hold.
<br>&gt;
<br>&gt; After a search, I found the first commit to add the infrastructure=
 is dfd402a4c4baae42398ce9180ff424d589b8bffc kcsan: Add Kernel Concurrency =
Sanitizer infrastructure, right after 5.4-rc7.
<br>&gt; Do you mean "git cherry-pick v5.4-rc7..50a19ad4b1ec"
<br>
<br>No.
<br>
<br>See "git help log". Specifically "a..b" means "list all the commits
<br>which are reachable from b, but not from a". Because we only want
<br>KCSAN related commits, the above is correct. Try it! You can also
<br>check what commits you'll get by sanity-checking with 'git log'.
<br>
<br></blockquote><div><br></div><div>I see. I am a Git newbie. Thanks for y=
our detailed explanation.</div><div>&nbsp;</div><blockquote class=3D"gmail_=
quote" style=3D"margin: 0 0 0 0.8ex; border-left: 1px solid rgb(204, 204, 2=
04); padding-left: 1ex;">Thanks,
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
om/d/msgid/kasan-dev/43db662c-ac04-4ba0-803f-2e7f8c3bdd55n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/43db662c-ac04-4ba0-803f-2e7f8c3bdd55n%40googlegroups.com</a>.<b=
r />

------=_Part_3601_2075134254.1606137372517--

------=_Part_3600_624009885.1606137372517--
