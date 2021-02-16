Return-Path: <kasan-dev+bncBCC5HZGYUYIRBRPJV6AQMGQETALQ4RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3720C31CE29
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 17:37:26 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id f132sf6213739oig.13
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Feb 2021 08:37:26 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zG2BcdiJJ4tJXqTbLRWvkmTS1IDD7gb/zUEdH5j4+vM=;
        b=VFM4lOgppTjlcLqlUQkorrp7Qszg6hUoEmnVS3uaPqEwr/qZ9EUB0Y4xmX9ML4uqKx
         lEMT6FC7ekbpMVEgxqWzESwbj3Eab8UkjSyy+scUdiJbJ1UCprusR4L/dZdrBd4R6dHo
         yA75VDRXu6xXlpNBByaVv1EL54QNC3FirPa0y9onp1MmXEYu+bcwtcolIRAzXqbYc1on
         EmYhXR0DQJAajS1MNvM0x3pVyOhu64zq++E9lDKMY6Zhwxq7SFInrrF9J/CjhofSZvyU
         e2u4gzWMoRBgZoXmoOSbnzAvjEMrgiV0L91ynj6IusRuL0oyWwyhcGBiUMRN87LUAeED
         Zjvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zG2BcdiJJ4tJXqTbLRWvkmTS1IDD7gb/zUEdH5j4+vM=;
        b=EOZ7rWYG30YZE0w4IksnGVIHjDqUEBJA2z7fwV8vXsUxsNcsEoF3/+UL+jF3KO06Yu
         f5CSN+5pmqpMZs8tTSgY0BqxINIIDmd/We1qm5+VjgUY3rzrzgoZHNoe1vCBxJWddjPv
         oa81U9fYArnltyD78B86hRLSIeDdLcghBH7jwGr2pyft6+ZiLcUh828p5tEMsPNHKp/A
         4WaGnh9E8/bOSDQVr0M+jQZMQNqfcurPTW39/cLFaV9UPgdna4a8D3G5y7TJjGgewdS0
         raTiJBju+LuUWuz9V1tJkdhNo16TH3VbgddwFpq5SXKi4O6ajlBwx8JdhRvyQnQY+u9j
         ig/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zG2BcdiJJ4tJXqTbLRWvkmTS1IDD7gb/zUEdH5j4+vM=;
        b=EcCkjBfDMcP/fV0/ujjgJv3VKtFYJhPMIARaoU+VJXbn4wMYc7b3SWLiE8rEmODhVF
         5PLNPbHOn+dKlGauKiWE03V76m9Po2lDUv0Mp0yMzh6UhBY15mbtkWCB9qChuze/3n93
         j4FpDIU2gQ1rFPn/j1m2frqyS5TXLK2ynQ+eqQQ7vCGf5rpVSdojIfM+YqXkdejr9T3T
         vHgCMQYW751wlTJzrWmx7r4D3ixbt1HfmPBaizGObX/8TvYTGmp7vqlWjY/1BNvPA+kh
         my4clLGLGdqe5w74p8zj+AY3+8cgFlplTMhp3NOSpxQVVMDAYQ+WKhig2p+lbIvygIJ8
         VreQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sX9I9ZszxBEFRNXFA0nqluUO6gOKvIwmX9Ogc9w3S6INq4FfQ
	c3pJC7meKouTP/8D27m/KQw=
X-Google-Smtp-Source: ABdhPJyB3EHQ2QudrKdzPQqTVRUDHIBaVDqjEbEsmPpM/JAq4HogtRWp1xf0syL8sHJKEn/whehGIA==
X-Received: by 2002:a05:6830:1d63:: with SMTP id l3mr15043733oti.314.1613493445260;
        Tue, 16 Feb 2021 08:37:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9c89:: with SMTP id z9ls1159540ooj.1.gmail; Tue, 16 Feb
 2021 08:37:24 -0800 (PST)
X-Received: by 2002:a4a:1bc2:: with SMTP id 185mr11225580oop.58.1613493444861;
        Tue, 16 Feb 2021 08:37:24 -0800 (PST)
Date: Tue, 16 Feb 2021 08:37:24 -0800 (PST)
From: Shahbaz Ali <shbaz.ali@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <c8763b30-cc09-40c1-ac50-774c99ee1712n@googlegroups.com>
In-Reply-To: <CAAeHK+z2FS0tZxPs73oJBX80mRkLWKyguT72bv2XZ9Db57NCrg@mail.gmail.com>
References: <745fe86a-17de-4597-8af3-baa306b6dd0cn@googlegroups.com>
 <CAAeHK+z1k3Y3qQWwYWa5ZuZdYtR+sqF9CSauoeLfGqR=qcdyDw@mail.gmail.com>
 <3ab303b3-1488-4c47-91db-248138ab5541n@googlegroups.com>
 <CAAeHK+z2FS0tZxPs73oJBX80mRkLWKyguT72bv2XZ9Db57NCrg@mail.gmail.com>
Subject: Re: __asan_register_globals with out-of-tree modules
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_8754_916760679.1613493444453"
X-Original-Sender: shbaz.ali@gmail.com
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

------=_Part_8754_916760679.1613493444453
Content-Type: multipart/alternative; 
	boundary="----=_Part_8755_1773345343.1613493444453"

------=_Part_8755_1773345343.1613493444453
Content-Type: text/plain; charset="UTF-8"

Thanks, I will take anything I can get!

Shahbaz

On Tuesday, February 16, 2021 at 4:16:13 PM UTC andre...@google.com wrote:

> On Tue, Feb 16, 2021 at 5:02 PM Shahbaz Ali <shba...@gmail.com> wrote:
> >
> > Thanks Andre,
> >
> > Unfortunately, due to the nature of the system, I do not have an easy 
> option to update it other than apply the 4.9 LTS patches (which I have done 
> already).
> >
> > Do you think it'd be possible for me to backport KASAN from the current 
> version?
>
> You can try backporting KASAN patches that mention changing global
> variables handling, maybe that would help.
>
> Backporting all KASAN patches is possible, but that's a lot of work. I
> backported KASAN to the 4.9 Android common kernel two years ago, the
> patches are here:
>
> https://github.com/xairy/kernel-sanitizers/tree/android-4.9-kasan
>
> But there have been a number of changes since then.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c8763b30-cc09-40c1-ac50-774c99ee1712n%40googlegroups.com.

------=_Part_8755_1773345343.1613493444453
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Thanks, I will take anything I can get!<div><br></div><div>Shahbaz<br><br><=
/div><div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">On T=
uesday, February 16, 2021 at 4:16:13 PM UTC andre...@google.com wrote:<br/>=
</div><blockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; borde=
r-left: 1px solid rgb(204, 204, 204); padding-left: 1ex;">On Tue, Feb 16, 2=
021 at 5:02 PM Shahbaz Ali &lt;<a href data-email-masked rel=3D"nofollow">s=
hba...@gmail.com</a>&gt; wrote:
<br>&gt;
<br>&gt; Thanks Andre,
<br>&gt;
<br>&gt; Unfortunately, due to the nature of the system, I do not have an e=
asy option to update it other than apply the 4.9 LTS patches (which I have =
done already).
<br>&gt;
<br>&gt; Do you think it&#39;d be possible for me to backport KASAN from th=
e current version?
<br>
<br>You can try backporting KASAN patches that mention changing global
<br>variables handling, maybe that would help.
<br>
<br>Backporting all KASAN patches is possible, but that&#39;s a lot of work=
. I
<br>backported KASAN to the 4.9 Android common kernel two years ago, the
<br>patches are here:
<br>
<br><a href=3D"https://github.com/xairy/kernel-sanitizers/tree/android-4.9-=
kasan" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://w=
ww.google.com/url?hl=3Den&amp;q=3Dhttps://github.com/xairy/kernel-sanitizer=
s/tree/android-4.9-kasan&amp;source=3Dgmail&amp;ust=3D1613579792596000&amp;=
usg=3DAFQjCNFH3wYKs0_fSvJSXL-a2qxh1Cz3tA">https://github.com/xairy/kernel-s=
anitizers/tree/android-4.9-kasan</a>
<br>
<br>But there have been a number of changes since then.
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/c8763b30-cc09-40c1-ac50-774c99ee1712n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/c8763b30-cc09-40c1-ac50-774c99ee1712n%40googlegroups.com</a>.<b=
r />

------=_Part_8755_1773345343.1613493444453--

------=_Part_8754_916760679.1613493444453--
