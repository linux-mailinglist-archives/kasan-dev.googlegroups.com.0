Return-Path: <kasan-dev+bncBDAOJ6534YNBB64SXG4AMGQE4E632RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id CA86899E499
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 12:52:45 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-539ea0fcd4bsf2246374e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:52:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728989565; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jd+I8f77vqx5FkTsfuS4xeH6ZMW7abxlOV+DZfLQ8UJuwMU6pFbYpSMLRbZOcxqEqM
         EB/GnaByFNEznJUsy1xKIxPlNCtv6WnbAaASbnlha2ZQ1YG7YFvtUlw266THHsoKVsXf
         2jff5mjEoqwG7UgJvXK6RGNjpXGOkThC3ub7v1LDe//Dc1GCqG+QzAjD/VJUnDKJgBJe
         4dzjHr2+GAwBPtae9gJOgoRMceUJkS7vIN1T6kvxFFrFjIRrWRZDll3NuQRncA/l+QPY
         PIjRln7S0zYIWvDRx+OT4xKPcsu/vki3owD7OoMepk1abdfOvwaDl3q1UE81vbGU6oPp
         sWmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Cq7T4v5dznHJ+47mHt2G9Gj+/o/j5cXZauqIcgpMJ7o=;
        fh=0HhXDNRH0+sRY75VKEaLi/DQ2VlmyHA4QzLv2F1WE80=;
        b=XoL419sUHWK4xUcZmijXNww5YurABl0vpRJEx4suwNZcH/KSeZbdKGgmuAz0OByXcW
         QcmhHWoTq+q77Gfwv8V4MC+gM7JocEta+45b9dY1ghg9fGvnRXDbWzqEigyLURFXbfRA
         xX7fuluzR/KhTnWputXbPVNBY5481gpQzhObbIoOvc7dOExC7/p41wWb8j3vI0huOhWz
         oAeCFroMzkMkgjcB2V4tE+NbawxUg9CtnVxB7bFZy4LJuTx26Dd0nnxbwZX9aohGeE8k
         zhN1Xx18SGPiU6YBhxv38bef6lFzlmVnw866fbga/o7kxVj7QiERfxPL+IivTTpxllWV
         zypQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WiHEp4cT;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728989565; x=1729594365; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Cq7T4v5dznHJ+47mHt2G9Gj+/o/j5cXZauqIcgpMJ7o=;
        b=BKjhapLFMhRkl89AZh8wQ9TT/kNjCawZN68IsIbDNk57uE2JGL8ge5bBjw+/jpuM7T
         I6Yrx+3mf6N5vW2QMxUFdF+tnWtHGcJel8YUUfwaHPwT1kGMrth5lLcDmUUoICbBUKx9
         4sy6y/8g0KY3AcOTBf9ODcZJ7ccXMNdll8OCXaELlDUPOs0untJkQ+5UuTZCCWn9BpmL
         GyID1JfiiDUBZiUxdx2Dk5Iu4aR3PWQO7eWqvZ5tp7ruEzuSBA7xAxraJFP6joJ5L4ob
         q2Joyx9sfPwW2lNOiSWHmczhy50h1vDU0zUTa5T/OgIV4ZUSmD0X0uA5jy9EbWCymnVn
         y31A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728989565; x=1729594365; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Cq7T4v5dznHJ+47mHt2G9Gj+/o/j5cXZauqIcgpMJ7o=;
        b=GP4n+Q/5dgR6xlUFRhPHAMb6uExHO1mKTnXKiqKGtE2BGLgWvm/nwn0ezLcLuQpXB5
         qxWOBlcr4e+St9E+Wna3hnjuU54waSmgvdglNjit46BpH46u1ERno2zbDC9Y9JoUMTmD
         xVHBiuhoOyMFvBM1Ot9k8SJHT0ON5Ub4URy0omOTgq/eWDGeTbMnnbGdt8QRR3J9ALpG
         B8umZ7USYaQtFcJT+epVNPpCOXzrflILGV+nYhLBoXT1LXsnQNv6HVzGo7PZqNvLP079
         ukOc5bZV6GCjGAgpI+p3280e0XVdsNUN7w+uwtL24AqOsm88Nn0x0yARn1hdJuzeXmgW
         ni6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728989565; x=1729594365;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Cq7T4v5dznHJ+47mHt2G9Gj+/o/j5cXZauqIcgpMJ7o=;
        b=WKGqK6Oe8n3dSmQ5qd9QDy84o5MGCYmnD5OuIQ6H4owpfCz5LyUaw9Cx8s5n4Xv/vO
         PAOtq5jM8XCWcMm6sKhcgBYWx7lnR5rexnVN8G+uiAeiL1Iin1GR5ZeoCTvF9yiVbEl7
         8q9+Z9dbbT78cKHDqlG9kAXLkLV4QvxJIdYmu6WNvpvxA0I92m1wjrl4QL9yjQZqzJXZ
         au6G55n5TJ3P6JyzMm7txStVCtk4PbjbSsWT98LG85VXlL0wGwzSK2WEwiaMW5wCz+jM
         Xf4AmkvxufkbLI4xAajXJzvZO9KdIj+JupSUN0BWwpp9ThmfhKdyhhej1IfWt1H5+qTs
         pejg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWWYP6ydiLoYE+rX6LxqYZiyKc61+IOmgy4PnEeoSkKc52vwg5sHq1z1VNFxN2qnupkHedI0Q==@lfdr.de
X-Gm-Message-State: AOJu0Yx2kfUjqHEENsurqV+B1HDE58WA5q6VpH5EIfhwyIOiZuMGuczC
	TYP1bHdMsX3CFamOZC3WfNCMhU0IaeIQ+to10BbOFMjdqVo7b+tk
X-Google-Smtp-Source: AGHT+IFe0MqvPkJopZOx29gr5sOEfJmuk79FKYQ3QHZCsaU2wAJ+Bn3sQx3pv1U31EnWRZu/ElggZQ==
X-Received: by 2002:a05:6512:2307:b0:539:964c:16b4 with SMTP id 2adb3069b0e04-539da5ae44emr6161728e87.58.1728989563515;
        Tue, 15 Oct 2024 03:52:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:334d:b0:539:fbe2:28a0 with SMTP id
 2adb3069b0e04-539fbe22a27ls304745e87.0.-pod-prod-03-eu; Tue, 15 Oct 2024
 03:52:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXptO0oLOegifoQ03JRtv7NgTzlNHouYpQy8PNnh9ifz27lbgURWyVl+NAZxgptRSU3ZPum2FuHpTw=@googlegroups.com
X-Received: by 2002:a05:6512:1092:b0:539:f5a9:b224 with SMTP id 2adb3069b0e04-539f5a9b44dmr3573171e87.11.1728989561318;
        Tue, 15 Oct 2024 03:52:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728989561; cv=none;
        d=google.com; s=arc-20240605;
        b=Un0QVGa94dimIsQE/1Ln+S2hWHMId2a79sdaHYFeezDhKTQv4fZGdZWaYqXVoQSChe
         93ENpW+C1suJRwJ4WDUlcve335h8MNCcIve8puLp7cTUT8ahBJVvTvlwqF01xYARPjy1
         BmjSVOIFfGWHxp4jYo09evj3zA2SLgBAK/m8AsmwgEeoK7vhy8WsVtbar0SOTufRGJhT
         6p1Wj4rBoyYZFMAYdLvg84PtLnzEua6TuvjEq2g2m0o+iyZzqZBFmNpY3JAMLhuhdBgP
         7B2kIrxYX6zsRYtXItOheE/4tykhgOYu5M+/UZieDw+7k6bw9EYMS2lKshBsiA827fVQ
         vRMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=miCofaLTCliOiaggNDs4P5r/0poFiwum/y0l9beo+ZU=;
        fh=ehGxujcVd8ZySYJvMeMkGhFxXr44hK2wV1hlgx4R/+w=;
        b=Nse5pmzQKfQm8cPMec0NrXFow+UFWdmF4Y0OYACnVWjl8KMQ/agwvetfoODkAtzomo
         JblEI/7pH3l+kKIwPhVE2Ea3HHI8SQjfVo9fbP6glpBpIgKRjPDvPd90+R6h668fATyN
         fn41UlA6Huja9kOibxor1EE2AmJteyaWGrwGQD0Tf0eefVB9HO0+bV5RXQ8/RuamPqOZ
         SPY3u8SDXk63p3j/fnd5SyhNHqWVtvh1CcgNaTMo5/8I2PVK8HhakG6F2SSa0cBLmYXm
         DsAfV1n3LwOlb/QtJ/iQMgzT4lapBsTECZoKEUAlcaSUaZeEMpNKFsBowhxIFIwmKHeO
         kx7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WiHEp4cT;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x533.google.com (mail-ed1-x533.google.com. [2a00:1450:4864:20::533])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53a00006d6asi39723e87.7.2024.10.15.03.52.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Oct 2024 03:52:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::533 as permitted sender) client-ip=2a00:1450:4864:20::533;
Received: by mail-ed1-x533.google.com with SMTP id 4fb4d7f45d1cf-5c949d60d84so4835919a12.1
        for <kasan-dev@googlegroups.com>; Tue, 15 Oct 2024 03:52:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU72WgeTl+PuXgofIntk+x5eL450/9G9bD4DdAQqEcICM9+A/p+AW5cxRs9n7jUs8sW1q5hAa6sBYM=@googlegroups.com
X-Received: by 2002:a05:6402:5188:b0:5c9:59e6:e908 with SMTP id
 4fb4d7f45d1cf-5c959e6f56amr9476072a12.6.1728989560452; Tue, 15 Oct 2024
 03:52:40 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZcyrGf5TBdkaG4M+r9ViKDwdCHZg12HUeeoTV3UNZnwBg@mail.gmail.com>
 <20241014025701.3096253-1-snovitoll@gmail.com> <20241014025701.3096253-3-snovitoll@gmail.com>
 <20241014161042.885cf17fca7850b5bbf2f8e5@linux-foundation.org> <CA+fCnZcwoL3qWhKsmgCCPDeAW0zpKGn=H7F8w8Fmsg+7-Y8p3g@mail.gmail.com>
In-Reply-To: <CA+fCnZcwoL3qWhKsmgCCPDeAW0zpKGn=H7F8w8Fmsg+7-Y8p3g@mail.gmail.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Tue, 15 Oct 2024 15:53:35 +0500
Message-ID: <CACzwLxgJaOL9RXkhAZEosmFDzp-D4=gGfhSh3d5scBRBaq76pw@mail.gmail.com>
Subject: Re: [PATCH RESEND v3 2/3] kasan: migrate copy_user_test to kunit
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 2023002089@link.tyut.edu.cn, 
	alexs@kernel.org, corbet@lwn.net, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	siyanteng@loongson.cn, vincenzo.frascino@arm.com, workflows@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WiHEp4cT;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::533
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Oct 15, 2024 at 6:18=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Tue, Oct 15, 2024 at 1:10=E2=80=AFAM Andrew Morton <akpm@linux-foundat=
ion.org> wrote:
> >
> > On Mon, 14 Oct 2024 07:57:00 +0500 Sabyrzhan Tasbolatov <snovitoll@gmai=
l.com> wrote:
> >
> > > Migrate the copy_user_test to the KUnit framework to verify out-of-bo=
und
> > > detection via KASAN reports in copy_from_user(), copy_to_user() and
> > > their static functions.
> > >
> > > This is the last migrated test in kasan_test_module.c, therefore dele=
te
> > > the file.
> > >
> >
> > x86_64 allmodconfig produces:
> >
> > vmlinux.o: warning: objtool: strncpy_from_user+0x8a: call to __check_ob=
ject_size() with UACCESS enabled

I've missed this warning during x86_64 build, sorry.

>
> Too bad. I guess we have to duplicate both kasan_check_write and
> check_object_size before both do_strncpy_from_user calls in
> strncpy_from_user.

Shall we do it once in strncpy_from_user() as I did in v1?
Please let me know as I've tested in x86_64 and arm64 -
there is no warning during kernel build with the diff below.

These checks are for kernel pointer *dst only and size:
   kasan_check_write(dst, count);
   check_object_size(dst, count, false);

And there are 2 calls of do_strncpy_from_user,
which are implemented in x86 atm per commit 2865baf54077,
and they are relevant to __user *src address, AFAIU.

long strncpy_from_user()
   if (can_do_masked_user_access()) {
      src =3D masked_user_access_begin(src);
      retval =3D do_strncpy_from_user(dst, src, count, count);
      user_read_access_end();
   }

   if (likely(src_addr < max_addr)) {
      if (user_read_access_begin(src, max)) {
         retval =3D do_strncpy_from_user(dst, src, count, max);
         user_read_access_end();

---
diff --git a/lib/strncpy_from_user.c b/lib/strncpy_from_user.c
index 989a12a6787..6dc234913dd 100644
--- a/lib/strncpy_from_user.c
+++ b/lib/strncpy_from_user.c
@@ -120,6 +120,9 @@ long strncpy_from_user(char *dst, const char
__user *src, long count)
        if (unlikely(count <=3D 0))
                return 0;

+       kasan_check_write(dst, count);
+       check_object_size(dst, count, false);
+
        if (can_do_masked_user_access()) {
                long retval;

@@ -142,8 +145,6 @@ long strncpy_from_user(char *dst, const char
__user *src, long count)
                if (max > count)
                        max =3D count;

-               kasan_check_write(dst, count);
-               check_object_size(dst, count, false);
                if (user_read_access_begin(src, max)) {
                        retval =3D do_strncpy_from_user(dst, src, count, ma=
x);
                        user_read_access_end();

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACzwLxgJaOL9RXkhAZEosmFDzp-D4%3DgGfhSh3d5scBRBaq76pw%40mail.gmai=
l.com.
