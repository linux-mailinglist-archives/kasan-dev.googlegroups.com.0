Return-Path: <kasan-dev+bncBCC5HZGYUYIRB3NQZ2AQMGQEYGE3E3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 46BDD32153D
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 12:41:34 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id e9sf6081776oiw.4
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 03:41:34 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iz2oj/ttaOppyZUXkGpjLp5Mg+MeqnxUo2QRdZiKleo=;
        b=JEZsWEiHdWYEHse4Ga3rC2odGDb1Ws5K136dIiFUibUp4bLQRhNiw5wpCea8ZJACDJ
         9OVRuDnWyOeqg6zIbi50xdotL5NF0iWKO9wL819OeP3CiPEMe/2NIv1Sz8hoe+gEySh9
         QnB0ZHQrl2dsEresGX5zZWTgUMSQnu9cdHxrNpd9gYp7E1fbVGgnUXEk9Q720mj2rF+4
         ARcDQP7zKSxu1M64/qIjsR7sA5sY2oE9T4Y9EW4aRbHpIo/aiocSa4BwHaGfRBsi9Si0
         7nmgCUyAEZ63OX5eioo35XajIDPtXSdpmvmFZ+lLFrGeqoM66pj+ICoP7l9QBD+o2/MS
         olWA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iz2oj/ttaOppyZUXkGpjLp5Mg+MeqnxUo2QRdZiKleo=;
        b=ZQFZHtkvCij2y8QUfleVFwX1BHFpiizZD8YWjRaYEFRgJVRNVD7P8qgCIxzLGl5WMU
         uZ6cJw/Ycwxi5Uc0iLjo5XXQJPSkkM85iMsgRitUHv1WwrfaKmOeO4sEYrxjfWsGJQ/N
         8U44LlsZNMVyOJKtUMhpaslggZEFuyPIR/LfNTycUo5YmIZpN78DlBG39XTnPgCAvZ02
         8NjaDYvmuktCqtfUQ//9XPgSTssSIKtGZkbCGSBUFTlQKBK/HLjUgectF/it4962RJm+
         L504iDpzN1HmzPPWIZjPpYmKyylcDrvSo20NvS1TOjbO8RZiQMvRhyqxc77vv7t4eL70
         sNag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iz2oj/ttaOppyZUXkGpjLp5Mg+MeqnxUo2QRdZiKleo=;
        b=PX1yoAl5X6MAiCupJUV1Riaqhq0zaUFaannRPDtCpku14hQG8+RA6eqdUFQx558Il6
         dMoJW2Mt+SwyuDfhZVaYPEAKoaVWUjg10NyoSeAFFwfFq7SlzePfuuCYChuryQx7sRK3
         QfRaBWFaQFmHMIzhyEYM3ROk2G+Tg9NHP/Pyqg/viZnnH+Wd5MzeM1b0qKw2/h0AYrQU
         A3eJG2E7W0UGNyw8jh8bXhN8a36aVH9aKK5KGcU7RUhwl1qN2lfOVfem2JjCbCFZY95V
         J0WfqP4ItPdmNj4pPPzO/XGbNkeq1RA02dFepvFKChRc5YRjkk8/tXxNCuqwEqi3xN4R
         77Uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531u2A2e7I+7dBXiN+/+LM6YO7Jx6qLWs6VUMzRkff6YrGdgNY68
	PsiVA+iZ1Cj8TSc2yOu4hhs=
X-Google-Smtp-Source: ABdhPJwguExA2U+ZPW/ZR+ILkN8f3PTvOAMcvl89HF7zTmOtWawgReYnXbAsVBioQn15t6GU68qnSg==
X-Received: by 2002:aca:6256:: with SMTP id w83mr15800520oib.170.1613994093259;
        Mon, 22 Feb 2021 03:41:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9868:: with SMTP id z37ls984226ooi.6.gmail; Mon, 22 Feb
 2021 03:41:32 -0800 (PST)
X-Received: by 2002:a4a:9019:: with SMTP id i25mr16067908oog.8.1613994092720;
        Mon, 22 Feb 2021 03:41:32 -0800 (PST)
Date: Mon, 22 Feb 2021 03:41:32 -0800 (PST)
From: Shahbaz Ali <shbaz.ali@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <589d9334-7d65-4679-9c4d-2feea648d092n@googlegroups.com>
In-Reply-To: <c8763b30-cc09-40c1-ac50-774c99ee1712n@googlegroups.com>
References: <745fe86a-17de-4597-8af3-baa306b6dd0cn@googlegroups.com>
 <CAAeHK+z1k3Y3qQWwYWa5ZuZdYtR+sqF9CSauoeLfGqR=qcdyDw@mail.gmail.com>
 <3ab303b3-1488-4c47-91db-248138ab5541n@googlegroups.com>
 <CAAeHK+z2FS0tZxPs73oJBX80mRkLWKyguT72bv2XZ9Db57NCrg@mail.gmail.com>
 <c8763b30-cc09-40c1-ac50-774c99ee1712n@googlegroups.com>
Subject: Re: __asan_register_globals with out-of-tree modules
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_1358_559312974.1613994092053"
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

------=_Part_1358_559312974.1613994092053
Content-Type: multipart/alternative; 
	boundary="----=_Part_1359_790983884.1613994092053"

------=_Part_1359_790983884.1613994092053
Content-Type: text/plain; charset="UTF-8"

Hi,

Managed to successfully port this to my 4.9 kernel.  However, I'm still 
having the same issue with my out-of-tree modules:

[   13.657676] KASAN got bad input address: 0000000000000190; (converted 
to:dfff200000000032)
[   13.669442] KASAN got bad input address: 0000000000000350; (converted 
to:dfff20000000006a)
[   13.680547] KASAN got bad input address: 00000000000001c0; (converted 
to:dfff200000000038)
[   13.691172] KASAN got bad input address: fffe4000016a3b48; (converted 
to:fffee800002d4769)
[   13.701755] KASAN got bad input address:           (null); (converted 
to:dfff200000000000)
[   13.712600] KASAN got bad input address: fffe4000016a66c0; (converted 
to:fffee800002d4cd8)
[   13.723101] KASAN got bad input address: 0000000000000050; (converted 
to:dfff20000000000a)
[   13.733607] KASAN got bad input address: 00000000000000d0; (converted 
to:dfff20000000001a)
[   13.744125] KASAN got bad input address: 0000000000000040; (converted 
to:dfff200000000008)
[   13.754642] KASAN got bad input address: fffe4000016a3c20; (converted 
to:fffee800002d4784)
[   13.765136] KASAN got bad input address:           (null); (converted 
to:dfff200000000000)
[   13.775619] KASAN got bad input address: fffe4000016a6880; (converted 
to:fffee800002d4d10)
[   13.786107] KASAN got bad input address: 0000000000000020; (converted 
to:dfff200000000004)
[   13.796587] KASAN got bad input address: 0000000000000060; (converted 
to:dfff20000000000c)

If I understand correctly, the __asan_register_globals is being 
instrumented into the out-of-tree module code during compile time; and 
during loading of the module,
this exported function is called with the kasan_global struct data 
(including memory address of the global)?

If that's the case, how is the address / kasan_global data determined for 
the call?  Is this hardcoded in by GCC during compile-time (in which case 
it might be a toolchain issue), or is it probing the kernel for that data 
during module load?

Basically, I'm just trying to track down why those global->beg addresses 
are wrong, whose fault it is, and why.  Any further help would be greately 
appreciated!

Thanks,
Shahbaz
On Tuesday, February 16, 2021 at 4:37:24 PM UTC Shahbaz Ali wrote:

> Thanks, I will take anything I can get!
>
> Shahbaz
>
> On Tuesday, February 16, 2021 at 4:16:13 PM UTC andre...@google.com wrote:
>
>> On Tue, Feb 16, 2021 at 5:02 PM Shahbaz Ali <shba...@gmail.com> wrote:
>> >
>> > Thanks Andre,
>> >
>> > Unfortunately, due to the nature of the system, I do not have an easy 
>> option to update it other than apply the 4.9 LTS patches (which I have done 
>> already).
>> >
>> > Do you think it'd be possible for me to backport KASAN from the current 
>> version?
>>
>> You can try backporting KASAN patches that mention changing global
>> variables handling, maybe that would help.
>>
>> Backporting all KASAN patches is possible, but that's a lot of work. I
>> backported KASAN to the 4.9 Android common kernel two years ago, the
>> patches are here:
>>
>> https://github.com/xairy/kernel-sanitizers/tree/android-4.9-kasan
>>
>> But there have been a number of changes since then.
>>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/589d9334-7d65-4679-9c4d-2feea648d092n%40googlegroups.com.

------=_Part_1359_790983884.1613994092053
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi,<div><br></div><div>Managed to successfully port this to my 4.9 kernel.&=
nbsp; However, I'm still having the same issue with my out-of-tree modules:=
</div><div><br></div><div><div>[&nbsp; &nbsp;13.657676] KASAN got bad input=
 address: 0000000000000190; (converted to:dfff200000000032)</div><div>[&nbs=
p; &nbsp;13.669442] KASAN got bad input address: 0000000000000350; (convert=
ed to:dfff20000000006a)</div><div>[&nbsp; &nbsp;13.680547] KASAN got bad in=
put address: 00000000000001c0; (converted to:dfff200000000038)</div><div>[&=
nbsp; &nbsp;13.691172] KASAN got bad input address: fffe4000016a3b48; (conv=
erted to:fffee800002d4769)</div><div>[&nbsp; &nbsp;13.701755] KASAN got bad=
 input address:&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;(null); (converted =
to:dfff200000000000)</div><div>[&nbsp; &nbsp;13.712600] KASAN got bad input=
 address: fffe4000016a66c0; (converted to:fffee800002d4cd8)</div><div>[&nbs=
p; &nbsp;13.723101] KASAN got bad input address: 0000000000000050; (convert=
ed to:dfff20000000000a)</div><div>[&nbsp; &nbsp;13.733607] KASAN got bad in=
put address: 00000000000000d0; (converted to:dfff20000000001a)</div><div>[&=
nbsp; &nbsp;13.744125] KASAN got bad input address: 0000000000000040; (conv=
erted to:dfff200000000008)</div><div>[&nbsp; &nbsp;13.754642] KASAN got bad=
 input address: fffe4000016a3c20; (converted to:fffee800002d4784)</div><div=
>[&nbsp; &nbsp;13.765136] KASAN got bad input address:&nbsp; &nbsp; &nbsp; =
&nbsp; &nbsp; &nbsp;(null); (converted to:dfff200000000000)</div><div>[&nbs=
p; &nbsp;13.775619] KASAN got bad input address: fffe4000016a6880; (convert=
ed to:fffee800002d4d10)</div><div>[&nbsp; &nbsp;13.786107] KASAN got bad in=
put address: 0000000000000020; (converted to:dfff200000000004)</div><div>[&=
nbsp; &nbsp;13.796587] KASAN got bad input address: 0000000000000060; (conv=
erted to:dfff20000000000c)</div></div><div><br></div><div>If I understand c=
orrectly, the __asan_register_globals is being instrumented into the out-of=
-tree module code during compile time; and during loading of the module,</d=
iv><div>this exported function is called with the kasan_global struct data =
(including memory address of the global)?</div><div><br></div><div>If that'=
s the case, how is the address / kasan_global data determined for the call?=
&nbsp; Is this hardcoded in by GCC during compile-time (in which case it mi=
ght be a toolchain issue), or is it probing the kernel for that data during=
 module load?<br><br></div><div>Basically, I'm just trying to track down wh=
y those global-&gt;beg addresses are wrong, whose fault it is, and why.&nbs=
p; Any further help would be greately appreciated!</div><div><br></div><div=
>Thanks,</div><div>Shahbaz</div><div class=3D"gmail_quote"><div dir=3D"auto=
" class=3D"gmail_attr">On Tuesday, February 16, 2021 at 4:37:24 PM UTC Shah=
baz Ali wrote:<br/></div><blockquote class=3D"gmail_quote" style=3D"margin:=
 0 0 0 0.8ex; border-left: 1px solid rgb(204, 204, 204); padding-left: 1ex;=
">Thanks, I will take anything I can get!<div><br></div><div>Shahbaz<br><br=
></div><div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">On=
 Tuesday, February 16, 2021 at 4:16:13 PM UTC <a href data-email-masked rel=
=3D"nofollow">andre...@google.com</a> wrote:<br></div><blockquote class=3D"=
gmail_quote" style=3D"margin:0 0 0 0.8ex;border-left:1px solid rgb(204,204,=
204);padding-left:1ex">On Tue, Feb 16, 2021 at 5:02 PM Shahbaz Ali &lt;<a r=
el=3D"nofollow">shba...@gmail.com</a>&gt; wrote:
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
kasan" rel=3D"nofollow" target=3D"_blank" data-saferedirecturl=3D"https://w=
ww.google.com/url?hl=3Den&amp;q=3Dhttps://github.com/xairy/kernel-sanitizer=
s/tree/android-4.9-kasan&amp;source=3Dgmail&amp;ust=3D1614078873032000&amp;=
usg=3DAFQjCNE_l-qHlA0iMp6wRppta5z71RuRsQ">https://github.com/xairy/kernel-s=
anitizers/tree/android-4.9-kasan</a>
<br>
<br>But there have been a number of changes since then.
<br></blockquote></div></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/589d9334-7d65-4679-9c4d-2feea648d092n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/589d9334-7d65-4679-9c4d-2feea648d092n%40googlegroups.com</a>.<b=
r />

------=_Part_1359_790983884.1613994092053--

------=_Part_1358_559312974.1613994092053--
