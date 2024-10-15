Return-Path: <kasan-dev+bncBDW2JDUY5AORB4XPXO4AMGQEJSOIEQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A48D99FC2F
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 01:17:09 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2fb4c08c02csf12781111fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 16:17:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729034228; cv=pass;
        d=google.com; s=arc-20240605;
        b=Izin1HgknzzKrPTx0ircfsqWuiRy75jw09zaGatWKpc9GQu15LXh/rb5cbxDP4APvO
         dTmVGVfG+oB30mbotxh35yI8wrZ46/MjbZvvmB1qZ/nsQh5oi3/FpCl2Fy2xZzWZ+iZx
         M8Rf2wFDrVuPeppSuuwz7sFHF5wqcEy0OS6c2mepv1ksGUPGXrhIPiAFMyG5Niy05csI
         fHeK3pVPsBZC35KNrnyWxI6i7V0/8xIYaNzhMn8dh3Xovmd306bjbWKZddUojkrqDdtk
         S/ntAJDjaQWNhxCJTcTllJMYlNwUwe5bzsD35jjvCo6SeAufTfa/9JOVkyhnmJdLVUWo
         yCGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=/EXhz/cfoKA2m+sOeOaPO04dL5sbSJEAhH4guIeI4i0=;
        fh=+wZIS9ZN9dxofp09kWHyWN1QIv7WhXwcd4vLfOnhol8=;
        b=aLC00on1mH+a8qnqeTUGiSvrMiqXUkYuQcv/HK3xxTw4X7nkaDz/wiUR+pL4bU8Lgk
         UcExpzPMt8VnTGTMYrwk881UGf3eaOl+00nLN8/f7xZlXGguhvNA8hmsGt3epXmCAwLR
         ogNL9z3ni4lgiYBpBwldO63UrgtvyxkK6Voz5ZThp2ua+ZAigRkfW+8iEgFj3EhRmv+l
         VyrJPNe1Pp3dW4Hr0b4a069TeS7G8RaXTM/rPktpRsoO8NmbBNceZD6/hbX886GehNxC
         AR2mLV1/r43Q/Js7ksI4sLbC/VzdZRJvR43EaHjRLO2ErQY85hTO/eKPiXK3VclaYDm/
         wbGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P592x+yT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729034228; x=1729639028; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/EXhz/cfoKA2m+sOeOaPO04dL5sbSJEAhH4guIeI4i0=;
        b=pNj/U8PbgmeuTaCE4XO9u6P3d8kQvKVdrmQa6uG0LPuOTyT0sPnMCzDP3YNbTqmDHe
         aqD6qUrsDVS6pBeZxnkF+oELpAfzZi6vHYFoYOs71Fka3bSO76WJcpZ4Sjfb2EHYRqfl
         WKzcQ+Nxrb5El/cZjdidNDkCG+69afYQb19blqJmPss9jW02WZd9VtCns9veni9xTOES
         4u/gRGiM9djtfGgpfk/tiQ1TYzJuzz11Vl9rxooZDXiVHRRe6VHPnnBAhK2HxIsxfUvo
         9YiUAX96BdVzP0wTY9PQ6eZ6IA8ZcxxVtlYb7bnq9ypdLeg4l1sDcleciuw4KMSwbtD0
         LEmQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729034228; x=1729639028; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/EXhz/cfoKA2m+sOeOaPO04dL5sbSJEAhH4guIeI4i0=;
        b=acSQJJSPUQnWkzMVBmFsGSUirrBQn2JVDa8Jdi4oX8K67BA/0BYoUVQEgpWllnDKwR
         /LOI/pYax7ycH2fH1zoSRkbUE9gt80b5UeQQWORcZDw09qnZi9+NKv69PeH74Rr1qsAs
         DF7IygI0b6/5gM16hCNUSzHK76MHfAQD4pfDogI1PQznZV8zg4JHe3gsgn/VbV5ipoLr
         qblQ44Dqn8QwlJkbDov7N7qnBdJGpJjXyfDDXy5ZzWgEbwk9TW7fHD9eaNyuGE5v1gH7
         AlycO7+mOlf8b8E0YJqbULHJiI7mkHJQSc457hxCxSlzgefPoxb8Vaqs3AryrTQZGefg
         XEEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729034228; x=1729639028;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/EXhz/cfoKA2m+sOeOaPO04dL5sbSJEAhH4guIeI4i0=;
        b=TMTrCZPS93QbG06Bmn0y1pMVIPQCAojNNWczLM0WlqEVAVOVmCME5E/TsBDAi+553L
         o3DLMbNgMLBo1WtFfvLr6uCjOoNOz47rltVY/kh7FAZjqg54AwMNtszQyJ97vx8YAPKY
         OygSbkA7KysDq/WCW/VzK1WLHrH1j5D1gc27zTWM6OSEvBNJg/vLF5UYPamF/crwPp1h
         SGLz6wj0xf9Y6IoxPbekjtk0/f9+dAiw1rN81UP9jYeO0SzuLA1utjRRyljgCCSFodRY
         IwW+a9lX8D7GRO03eXTHSqYrYGR7N6BY3O1wTrLQeYNcEYeMZvJN4nFqHvzfPcuWVT8V
         +Huw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKHaEGEtFHmMmwweCxJGbc8vl+RJEmcUNJsYX5b/s32CVTg7U5kN2IAzC+Tyse5n/APkJIxg==@lfdr.de
X-Gm-Message-State: AOJu0YzqclxFOz9A8Dy9r5G964XT5VmD/ObYJ+8oQtkZPdyEPAdlU2bZ
	b4bIDkd4r/X+WK5ktafCvpuygr6FUVYGoC0+IBtK3PTpx0PUGu02
X-Google-Smtp-Source: AGHT+IGPKSK3xdIXTgAFxbcW8Qu+oYwXTzOatKsoGv4qS2EM6ejrxfhurQhaqTiq4UAm4n9h45XhUw==
X-Received: by 2002:a2e:809:0:b0:2f8:c0bd:d65f with SMTP id 38308e7fff4ca-2fb32740b7fmr57763751fa.20.1729034226802;
        Tue, 15 Oct 2024 16:17:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2204:0:b0:2fb:3dc4:86ab with SMTP id 38308e7fff4ca-2fb3dc48742ls8407261fa.0.-pod-prod-02-eu;
 Tue, 15 Oct 2024 16:17:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAfC5zL3wtzzSbP8s0mcmASLus1uduaYsIWEUoBy4PLP6jOOYfy1/zmtZHGNZN5fhYe7pcsD9E1sQ=@googlegroups.com
X-Received: by 2002:a05:6512:2207:b0:539:f748:b568 with SMTP id 2adb3069b0e04-539f748b8f0mr4598903e87.32.1729034224697;
        Tue, 15 Oct 2024 16:17:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729034224; cv=none;
        d=google.com; s=arc-20240605;
        b=blBo7NycI0+ZyEAhNDWQw1fDPC+4ujUZ3P1YOPnoNfUPwBrA0scmHa9jjLFjji0YY7
         HVLwWBmiNHtql0g22Vnx/rLftluThn6onTbzMa4YPPGUuFnf0Yj942GdDE7veb4dmdTV
         Mb2Mfqacg7i9e1A2ALNys1256eYX/fVTXBXTixxjM0iW39qR+QgRzoUH6oDs1nIWBryp
         14iXtVT+WMD5ja4zSgdzQUWL73AVYAJea2u1GWIRPu9/SjkOzbUPfPBupCL7NuENmuzI
         E46fXHZJU33GUcrBEBIBeXC9yZcHH0GRjZEc06mY8A7ZclKAAsEz5UPOhHLbpBmOQRku
         RlRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=eD4CywG5G4jHbhFsfPy0Spq5T4P0b6fgkLacmkiZ4vE=;
        fh=/0flwIOW6d4UXBm82Csig+BWdB4HSh2oGlhH3QulQlY=;
        b=gf094FsUm2h2LmTnHqfEqbxpNxNN4ll+pH+BEJ1DOOvypqSyxKSt9D65uhK6gpmBmL
         8B8w+f5lqU26DxJbASZXDeaEZUZCwqhmLKXe3+FctJnf2xIBiebvc7PQRUHorI9wH+b/
         SxFv6Cr0CfwQnaWpLxciRwC4CqombbJ8x0zlW33t0vGLE3E2+o0jlUK0sb+mPKhw2CuP
         s6geW1w+PVv8fn7yUs912bixU19xVcooRZZPorFi05XtdP6dq60BK2rg9j7esGCWeven
         d7+obkvZBuljaIH9NTpEkn4ZwJthj5xQGXdp+7vv73Z2q+hU3zYFVeJb4m4Ho/UqLWSj
         JmgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P592x+yT;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53a0405b962si20577e87.5.2024.10.15.16.17.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Oct 2024 16:17:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-37d63a79bb6so2432578f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 15 Oct 2024 16:17:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUPGBGJ+nny452L5dpRbXtYaxySgt+V/1xt6Ijh5BIHaDUvv9fPjRLPdGd3niApYgGxi/RQvZZ4SPk=@googlegroups.com
X-Received: by 2002:a5d:6647:0:b0:37d:453f:4469 with SMTP id
 ffacd0b85a97d-37d551d506amr10150361f8f.22.1729034223715; Tue, 15 Oct 2024
 16:17:03 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZcyrGf5TBdkaG4M+r9ViKDwdCHZg12HUeeoTV3UNZnwBg@mail.gmail.com>
 <20241014025701.3096253-1-snovitoll@gmail.com> <20241014025701.3096253-3-snovitoll@gmail.com>
 <20241014161042.885cf17fca7850b5bbf2f8e5@linux-foundation.org>
 <CA+fCnZcwoL3qWhKsmgCCPDeAW0zpKGn=H7F8w8Fmsg+7-Y8p3g@mail.gmail.com> <CACzwLxgJaOL9RXkhAZEosmFDzp-D4=gGfhSh3d5scBRBaq76pw@mail.gmail.com>
In-Reply-To: <CACzwLxgJaOL9RXkhAZEosmFDzp-D4=gGfhSh3d5scBRBaq76pw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 16 Oct 2024 01:16:52 +0200
Message-ID: <CA+fCnZf8YRH=gkmwU8enMLnGi7hHfVP4DSE2TLrmmVsHT10wRQ@mail.gmail.com>
Subject: Re: [PATCH RESEND v3 2/3] kasan: migrate copy_user_test to kunit
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 2023002089@link.tyut.edu.cn, 
	alexs@kernel.org, corbet@lwn.net, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	siyanteng@loongson.cn, vincenzo.frascino@arm.com, workflows@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=P592x+yT;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Tue, Oct 15, 2024 at 12:52=E2=80=AFPM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> > Too bad. I guess we have to duplicate both kasan_check_write and
> > check_object_size before both do_strncpy_from_user calls in
> > strncpy_from_user.
>
> Shall we do it once in strncpy_from_user() as I did in v1?
> Please let me know as I've tested in x86_64 and arm64 -
> there is no warning during kernel build with the diff below.
>
> These checks are for kernel pointer *dst only and size:
>    kasan_check_write(dst, count);
>    check_object_size(dst, count, false);
>
> And there are 2 calls of do_strncpy_from_user,
> which are implemented in x86 atm per commit 2865baf54077,
> and they are relevant to __user *src address, AFAIU.
>
> long strncpy_from_user()
>    if (can_do_masked_user_access()) {
>       src =3D masked_user_access_begin(src);
>       retval =3D do_strncpy_from_user(dst, src, count, count);
>       user_read_access_end();
>    }
>
>    if (likely(src_addr < max_addr)) {
>       if (user_read_access_begin(src, max)) {
>          retval =3D do_strncpy_from_user(dst, src, count, max);
>          user_read_access_end();
>
> ---
> diff --git a/lib/strncpy_from_user.c b/lib/strncpy_from_user.c
> index 989a12a6787..6dc234913dd 100644
> --- a/lib/strncpy_from_user.c
> +++ b/lib/strncpy_from_user.c
> @@ -120,6 +120,9 @@ long strncpy_from_user(char *dst, const char
> __user *src, long count)
>         if (unlikely(count <=3D 0))
>                 return 0;
>
> +       kasan_check_write(dst, count);
> +       check_object_size(dst, count, false);
> +
>         if (can_do_masked_user_access()) {
>                 long retval;
>
> @@ -142,8 +145,6 @@ long strncpy_from_user(char *dst, const char
> __user *src, long count)
>                 if (max > count)
>                         max =3D count;
>
> -               kasan_check_write(dst, count);
> -               check_object_size(dst, count, false);
>                 if (user_read_access_begin(src, max)) {
>                         retval =3D do_strncpy_from_user(dst, src, count, =
max);
>                         user_read_access_end();

Ok, let's do this. (What looked concerning to me with this approach
was doing the KASAN/userscopy checks outside of the src_addr <
max_addr, but I suppose that should be fine.)

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf8YRH%3DgkmwU8enMLnGi7hHfVP4DSE2TLrmmVsHT10wRQ%40mail.gm=
ail.com.
