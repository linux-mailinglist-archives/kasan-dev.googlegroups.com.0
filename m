Return-Path: <kasan-dev+bncBCH2XPOBSAERBSG5536QKGQE6GVEZYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C7862C0788
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 13:44:57 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id v13sf1441505oos.4
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 04:44:57 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4qbp6PguUvjJZ/+yzZ32YAqQwjCWkWSiKzQ1dxOnKik=;
        b=lCQ24AeZ/di5Zs5+lL+8EUJiX/Bn+LxLxZYrqHWR18Y+zSYpj1Hz9FzNLTNJOcZr+K
         MZdbUnYAMDgcfPyvvmk2Wo1r/0Co6+DI2JWK0PuwKWNCQ74ns/XZRK8kQaQzWVs8Sh9e
         EXSIsnnLVmCJuwT7GV6daKpbF2fTq2vCyasv/5zD9v1EL6glkvUyZwiX3i1CnYGakDWa
         UnIHQbFTT8zqC5DyDYtF100Dtm3FwxpuYBFAL5vygVTZyuggeM956xVh4KS6A0pZ8npi
         4tvGGxiHg1/74BtI56HScQ5/KemxrRkGP9dVA04gk1yOXgvUqocR4of03nrr5f0S9F/Z
         MUdQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4qbp6PguUvjJZ/+yzZ32YAqQwjCWkWSiKzQ1dxOnKik=;
        b=U47oZBFnPJZ32aMkyi/I6ZKWLRedX3cXRKqzLk4QV2FipIKQyVdAevw1QSFwl/+eDJ
         cedDeufP3XZK1MM9fiIRNUsrg2y3h2JNYUWghG2eOEHiO+olo+p3fWnQNYPfHfqurSCV
         GfLokBELNMEPowFVH+Gx2rtmih2OZR+QijwCmWwKkvDZJYlMZrzNQQI+YHzfYbblSQpF
         QJDTHtSN1ybVAhisbSrYzvhCyvfrXHcdFmY077s9Z/S6uriVmosyrXKlGZ2z7UuiKa7I
         EHBWZoSu/2KSqoakvuy+tawpYEhlR75VS9YT4DCYkrtGeQGgHw6PilEtH8c1OnxlyFgl
         Xz8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4qbp6PguUvjJZ/+yzZ32YAqQwjCWkWSiKzQ1dxOnKik=;
        b=fC9lgAMHKvzIIyEi8TE3kHeogFSFgsHVLy6Wv86uV8SZRmrWDfpOtIzalvq4AudNY4
         a0OejCuUTkLOZryd+Fiu5p3X8dKRsvFsUHTVjrJ42m7J2RQYlWiVFOKfvzaZeKnzVl+v
         UiAyJ9NzBoNQ4mePpr7VTwhPG1W+hHRbwmQwMYehhgZpFHiTM6XS7GFXPX0Y/rkeFajC
         9DOf1nCo3PqLHtTHwWrTyr8D0K7q0lyIRk6ExIm0xT/1atnu1ruGay7MnioBoZVXF4kl
         9/SXQtK8749V/hK4p9iILcPeHlhIPkJALuu92dqDhvnUAbaK4uoHkIMl79THzZiOmdw8
         E7yA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GLVmT9DL7LH5brFcuRHylpbcy4gYiT7sWmtx8i6l0OXGcFrcl
	d+JQbWIyZZQ00xDobFixp0s=
X-Google-Smtp-Source: ABdhPJwZUBxLwL+7nPP0/bjSSVu1EebPfgBXxVvLH4B5JkTzLeoq/YMER/K0BoQlOsgb5cLcVTE2sw==
X-Received: by 2002:aca:b8c3:: with SMTP id i186mr10288749oif.78.1606135496095;
        Mon, 23 Nov 2020 04:44:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1118:: with SMTP id 24ls3297360oir.10.gmail; Mon, 23 Nov
 2020 04:44:55 -0800 (PST)
X-Received: by 2002:a54:4885:: with SMTP id r5mr3904050oic.34.1606135495514;
        Mon, 23 Nov 2020 04:44:55 -0800 (PST)
Date: Mon, 23 Nov 2020 04:44:54 -0800 (PST)
From: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <83c70bdd-4f74-421a-85bc-fd518f303ce1n@googlegroups.com>
In-Reply-To: <CANpmjNPm3U=aeuhv4CpqsxbkQj8SnKbauLmXyAu2b=8bCEg6pQ@mail.gmail.com>
References: <f4a62280-43f5-468b-94c4-fdda826d28d0n@googlegroups.com>
 <CANpmjNPsjXqDQLkeBb2Ap7j8rbrDwRHeuGPyzXXQ++Qxe4A=7A@mail.gmail.com>
 <8b89f21f-e3e9-4344-92d3-580d2f0f2860n@googlegroups.com>
 <CANpmjNPm3U=aeuhv4CpqsxbkQj8SnKbauLmXyAu2b=8bCEg6pQ@mail.gmail.com>
Subject: Re: Any guidance to port KCSAN to previous Linux Kernel versions?
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_3042_1788877232.1606135494693"
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

------=_Part_3042_1788877232.1606135494693
Content-Type: multipart/alternative; 
	boundary="----=_Part_3043_228980658.1606135494693"

------=_Part_3043_228980658.1606135494693
Content-Type: text/plain; charset="UTF-8"



On Monday, November 23, 2020 at 4:51:31 PM UTC+8 el...@google.com wrote:

> On Mon, 23 Nov 2020 at 04:18, mudongl...@gmail.com 
> <mudongl...@gmail.com> wrote: 
> > 
> > 
> > 
> > On Wednesday, November 18, 2020 at 6:05:45 PM UTC+8 el...@google.com 
> wrote: 
> >> 
> >> On Wed, 18 Nov 2020 at 08:09, mudongl...@gmail.com 
> >> <mudongl...@gmail.com> wrote: 
> >> > 
> >> > Hello all, 
> >> > 
> >> > I am writing to ask for some guidance to port KCSAN to some LTS 
> kernel versions. As KCSAN is already merged into upstream and works well to 
> catch some bugs in some kernel trees, it is good idea to port KCSAN to some 
> previous Linux Kernel version. On one hand, it is good for bug detection in 
> LTS kernel; On the other hand, it is good to diagnose some kernel crashes 
> caused by data race. 
> >> > 
> >> > Thanks in advance. 
> >> > 
> >> > Dongliang Mu 
> >> 
> >> There have been major changes to READ_ONCE()/WRITE_ONCE() in Linux 5.8 
> >> which make backporting non-trivial since those changes would have to 
> >> be backported, too. Your best bet might be looking at the version of 
> >> KCSAN at 50a19ad4b1ec: git log v5.7-rc7..50a19ad4b1ec -- but that is 
> >> missing some important changes, and I question the value in 
> >> backporting. 
> > 
> > 
> > Thanks for your explanation. That's helpful. 
> > 
> > Let's imagine a scenario: KASAN detects a UAF crash in an old Linux 
> kernel(e.g., 5.4, 4.19), but the underlying reason for this crash behavior 
> is data racing from two different threads with plain accesses(without 
> READ_ONCE/WRITE_ONCE). 
> > What I want is to backport KCSAN and test whether it could catch the 
> underlying data race before triggering the further UAF crash. This would 
> help us identify the underlying issue(two concurrent threads and the object 
> for data race) and fix the bug completely. 
>
> For debugging such issues, I'd run with a more aggressive KCSAN config 
> (regardless of kernel version): 
>
> CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=n 
> CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n 
>
> and lower 'kcsan.skip_watch=' boot parameter from default of 4000 down 
> to ~500 in decrements of 500 and stop when the system becomes too 
> slow. 
>
>
That's a good idea. I will try this config when testing my problem.
 

> > Therefore, if I try to backport KCSAN and test whether KCSAN catches 
> this special data race, is it still too complicated or need non-trivial 
> efforts? 
>
> See if 'git cherry-pick v5.7-rc7..50a19ad4b1ec' works. 
>

Quick question about the above command: cherry-pick requires the first 
commit(v5.7-rc7) is older than the second commit(50a19ad4b1ec). However, 

commit 9cb1fd0efd195590b828b9b865421ad345a4a145 (tag: v5.7-rc7)
Author: Linus Torvalds <torvalds@linux-foundation.org>
Date:   Sun May 24 15:32:54 2020 -0700

    Linux 5.7-rc7

commit 50a19ad4b1ec531eb550183cb5d4ab9f25a56bf8
Author: Marco Elver <elver@google.com>
Date:   Fri Apr 24 17:47:30 2020 +0200

    objtool, kcsan: Add kcsan_disable_current() and 
kcsan_enable_current_nowarn()
    
    Both are safe to be called from uaccess contexts.
    
    Signed-off-by: Marco Elver <elver@google.com>
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

However, in fact it does not hold.

After a search, I found the first commit to add the infrastructure 
is dfd402a4c4baae42398ce9180ff424d589b8bffc kcsan: Add Kernel Concurrency 
Sanitizer infrastructure, right after 5.4-rc7.
Do you mean "git cherry-pick v5.4-rc7..50a19ad4b1ec"
 

>
> >> In particular, we have the following problem: The kernel still has 
> >> (and before 5.5 it was worse) numerous very frequent data races that 
> >> are -- with current compilers and architectures -- seemingly benign, 
> >> or failure due to them is unlikely. The emphasis here should be on 
> >> _very frequent data races_, because we know there are infrequent data 
> >> races that are potentially harmful. But, unfortunately we're still 
> >> suffering from a "find the needle in the haystack problem" here. Which 
> >> means a backport isn't going to be too helpful right now because we'd 
> >> only like to tackle this problem for mainline right now. A better 
> >> approach is to backport fixes as required. 
> >> 
> >> We are slowly working on addressing these problems, the most 
> >> straightforward approach would be to mark intentional data races and 
> >> fix other issues, but that isn't trivial because there are so many and 
> >> each needs to be carefully analyzed. 
> >> 
> >> I recommend reading https://lwn.net/Articles/816854/ . 
> >> 
> >> Thanks, 
> >> -- Marco 
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/83c70bdd-4f74-421a-85bc-fd518f303ce1n%40googlegroups.com.

------=_Part_3043_228980658.1606135494693
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<br><br><div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">O=
n Monday, November 23, 2020 at 4:51:31 PM UTC+8 el...@google.com wrote:<br>=
</div><blockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; borde=
r-left: 1px solid rgb(204, 204, 204); padding-left: 1ex;">On Mon, 23 Nov 20=
20 at 04:18, <a href=3D"" data-email-masked=3D"" rel=3D"nofollow">mudongl..=
.@gmail.com</a>
<br>&lt;<a href=3D"" data-email-masked=3D"" rel=3D"nofollow">mudongl...@gma=
il.com</a>&gt; wrote:
<br>&gt;
<br>&gt;
<br>&gt;
<br>&gt; On Wednesday, November 18, 2020 at 6:05:45 PM UTC+8 <a href=3D"" d=
ata-email-masked=3D"" rel=3D"nofollow">el...@google.com</a> wrote:
<br>&gt;&gt;
<br>&gt;&gt; On Wed, 18 Nov 2020 at 08:09, <a href=3D"" data-email-masked=
=3D"" rel=3D"nofollow">mudongl...@gmail.com</a>
<br>&gt;&gt; &lt;<a href=3D"" data-email-masked=3D"" rel=3D"nofollow">mudon=
gl...@gmail.com</a>&gt; wrote:
<br>&gt;&gt; &gt;
<br>&gt;&gt; &gt; Hello all,
<br>&gt;&gt; &gt;
<br>&gt;&gt; &gt; I am writing to ask for some guidance to port KCSAN to so=
me LTS kernel versions. As KCSAN is already merged into upstream and works =
well to catch some bugs in some kernel trees, it is good idea to port KCSAN=
 to some previous Linux Kernel version. On one hand, it is good for bug det=
ection in LTS kernel; On the other hand, it is good to diagnose some kernel=
 crashes caused by data race.
<br>&gt;&gt; &gt;
<br>&gt;&gt; &gt; Thanks in advance.
<br>&gt;&gt; &gt;
<br>&gt;&gt; &gt; Dongliang Mu
<br>&gt;&gt;
<br>&gt;&gt; There have been major changes to READ_ONCE()/WRITE_ONCE() in L=
inux 5.8
<br>&gt;&gt; which make backporting non-trivial since those changes would h=
ave to
<br>&gt;&gt; be backported, too. Your best bet might be looking at the vers=
ion of
<br>&gt;&gt; KCSAN at 50a19ad4b1ec: git log v5.7-rc7..50a19ad4b1ec -- but t=
hat is
<br>&gt;&gt; missing some important changes, and I question the value in
<br>&gt;&gt; backporting.
<br>&gt;
<br>&gt;
<br>&gt; Thanks for your explanation. That's helpful.
<br>&gt;
<br>&gt; Let's imagine a scenario: KASAN detects a UAF crash in an old Linu=
x kernel(e.g., 5.4, 4.19), but the underlying reason for this crash behavio=
r is data racing from two different threads with plain accesses(without REA=
D_ONCE/WRITE_ONCE).
<br>&gt; What I want is to backport KCSAN and test whether it could catch t=
he underlying data race before triggering the further UAF crash. This would=
 help us identify the underlying issue(two concurrent threads and the objec=
t for data race) and fix the bug completely.
<br>
<br>For debugging such issues, I'd run with a more aggressive KCSAN config
<br>(regardless of kernel version):
<br>
<br>CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn
<br>CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn
<br>
<br>and lower 'kcsan.skip_watch=3D' boot parameter from default of 4000 dow=
n
<br>to ~500 in decrements of 500 and stop when the system becomes too
<br>slow.
<br>
<br></blockquote><div><br></div><div>That's a good idea. I will try this co=
nfig when testing my problem.</div><div>&nbsp;</div><blockquote class=3D"gm=
ail_quote" style=3D"margin: 0 0 0 0.8ex; border-left: 1px solid rgb(204, 20=
4, 204); padding-left: 1ex;">&gt; Therefore, if I try to backport KCSAN and=
 test whether KCSAN catches this special data race, is it still too complic=
ated or need non-trivial efforts?
<br>
<br>See if 'git cherry-pick v5.7-rc7..50a19ad4b1ec' works.
<br></blockquote><div><br></div><div>Quick question about the above command=
: cherry-pick requires the first commit(v5.7-rc7) is older than the second =
commit(50a19ad4b1ec). However,&nbsp;</div><div><div><br></div><div>commit 9=
cb1fd0efd195590b828b9b865421ad345a4a145 (tag: v5.7-rc7)</div><div>Author: L=
inus Torvalds &lt;torvalds@linux-foundation.org&gt;</div><div>Date:&nbsp; &=
nbsp;Sun May 24 15:32:54 2020 -0700</div><div><br></div><div>&nbsp; &nbsp; =
Linux 5.7-rc7</div></div><div><br></div><div><div>commit 50a19ad4b1ec531eb5=
50183cb5d4ab9f25a56bf8</div><div>Author: Marco Elver &lt;elver@google.com&g=
t;</div><div>Date:&nbsp; &nbsp;Fri Apr 24 17:47:30 2020 +0200</div><div><br=
></div><div>&nbsp; &nbsp; objtool, kcsan: Add kcsan_disable_current() and k=
csan_enable_current_nowarn()</div><div>&nbsp; &nbsp;&nbsp;</div><div>&nbsp;=
 &nbsp; Both are safe to be called from uaccess contexts.</div><div>&nbsp; =
&nbsp;&nbsp;</div><div>&nbsp; &nbsp; Signed-off-by: Marco Elver &lt;elver@g=
oogle.com&gt;</div><div>&nbsp; &nbsp; Signed-off-by: Paul E. McKenney &lt;p=
aulmck@kernel.org&gt;</div></div><div><br></div><div>However, in fact it do=
es not hold.</div><div><br></div><div>After a search, I found the first com=
mit to add the infrastructure is&nbsp;dfd402a4c4baae42398ce9180ff424d589b8b=
ffc&nbsp;kcsan: Add Kernel Concurrency Sanitizer infrastructure, right afte=
r 5.4-rc7.</div><div>Do you mean "git cherry-pick v5.4-rc7..50a19ad4b1ec"</=
div><div>&nbsp;</div><blockquote class=3D"gmail_quote" style=3D"margin: 0 0=
 0 0.8ex; border-left: 1px solid rgb(204, 204, 204); padding-left: 1ex;">
<br>&gt;&gt; In particular, we have the following problem: The kernel still=
 has
<br>&gt;&gt; (and before 5.5 it was worse) numerous very frequent data race=
s that
<br>&gt;&gt; are -- with current compilers and architectures -- seemingly b=
enign,
<br>&gt;&gt; or failure due to them is unlikely. The emphasis here should b=
e on
<br>&gt;&gt; _very frequent data races_, because we know there are infreque=
nt data
<br>&gt;&gt; races that are potentially harmful. But, unfortunately we're s=
till
<br>&gt;&gt; suffering from a "find the needle in the haystack problem" her=
e. Which
<br>&gt;&gt; means a backport isn't going to be too helpful right now becau=
se we'd
<br>&gt;&gt; only like to tackle this problem for mainline right now. A bet=
ter
<br>&gt;&gt; approach is to backport fixes as required.
<br>&gt;&gt;
<br>&gt;&gt; We are slowly working on addressing these problems, the most
<br>&gt;&gt; straightforward approach would be to mark intentional data rac=
es and
<br>&gt;&gt; fix other issues, but that isn't trivial because there are so =
many and
<br>&gt;&gt; each needs to be carefully analyzed.
<br>&gt;&gt;
<br>&gt;&gt; I recommend reading <a href=3D"https://lwn.net/Articles/816854=
/" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.g=
oogle.com/url?hl=3Den&amp;q=3Dhttps://lwn.net/Articles/816854/&amp;source=
=3Dgmail&amp;ust=3D1606212906755000&amp;usg=3DAFQjCNF0LCuj5JVN3YX3rFT39UFJ1=
AYCEA">https://lwn.net/Articles/816854/</a> .
<br>&gt;&gt;
<br>&gt;&gt; Thanks,
<br>&gt;&gt; -- Marco
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/83c70bdd-4f74-421a-85bc-fd518f303ce1n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/83c70bdd-4f74-421a-85bc-fd518f303ce1n%40googlegroups.com</a>.<b=
r />

------=_Part_3043_228980658.1606135494693--

------=_Part_3042_1788877232.1606135494693--
