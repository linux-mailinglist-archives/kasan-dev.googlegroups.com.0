Return-Path: <kasan-dev+bncBDW2JDUY5AORBC72VO4AMGQEQQFHMHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EE9F99B78B
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 00:49:48 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4312935010fsf4758585e9.3
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 15:49:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728773388; cv=pass;
        d=google.com; s=arc-20240605;
        b=bnvaxanyNRZi8grOBbOOLI159BVK2Ikc3NBXqJtSKuFlmnDEujD0o/j7yJfWWL8vds
         a+SufgQ9rfai8zqUt0hAmAeDGTHwovrv6GEI0L1v9iuzwrX4OeEBScmYca2kQJG/yjre
         NemAhNhVEHanQulPwW7GtPGgaw5UZTO1pOtCzp6zZL0uwvnTSHQovkThipOOEW/X1NSt
         LK8J0EZkTFon5jKJmn3We3YdAFVKdCkBVB1s8qCNaXiJGIF2VOyFzGce9bx7/pCNRvsF
         90W8hZxPbCA3QfhYZ4XSVdn1+4bIOEqSxXpTCvnQuXb/LRSGk3aanP5eMLQntW8s4r8t
         8UXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=20NF4tqMkiBbTWgWiCl4WQg/jcaDcrbz1qUQrjzy/qw=;
        fh=HQkPB4Lb7OJecaEMFR2Zrt04BDIkFqJlbRdp2LjclSk=;
        b=XRI93FzNOFmYAXnHqvmDWOXe0S/OZe9Xmaas4kP3pR3fBqglfB+4N617dHcW5IyR9D
         uTdLtO37N19h9WzK9fRLCVf9ltvRM6ZeM3WVqh8hN+FBcH5mB3aQ0bd6GVeudOGVFIK+
         22T2nOEDfhBR7EnOuCGedyAffVRzjSPqd9+zmm5LVi7h51Syn18sIq5yi2JzdZOrcfBY
         yfAA0bKH1GhWXcKzw561Mrk+QN1NxQoa8+goHJPlyERaH9repDmWs+F4engTB9MbUQmp
         1KU4EiTITTUAg7MRpL3ldWXIFlTbPHPc0pD4JEaEV9581S/NBIlzxWK0Xn4bdeREM5XG
         QxKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cVxLFQXk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728773388; x=1729378188; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=20NF4tqMkiBbTWgWiCl4WQg/jcaDcrbz1qUQrjzy/qw=;
        b=JOEsvNiQdKDDxl5DcPfpSUdoygjrSSwJzzVcR0wFra/FVo6210XMGXVoLSaRac2DeM
         hZLAq776lCMZW57+6ScV+MsMzatWEa7m1bgsr9XOuxS4EpGJZkmCqu9xzwGFv6ijmjf7
         6jL9qhHdVi2D1F/tUdHDaAREUsyKm9M+WHgHh5Dmn/VrnBc/7aBoRy/pVVolxQJh/oiD
         uWeZ+f+sxywIA8f2ZlnN7WXsU2z4Hf0cnoqMCA/+dV7EbbfrS6NtJUyPGEMWqXlpjzpX
         IsbroZJxB4bNlD9c8ZStreF73PjsRFQmxPK2ZqQAUsyER4625dHtBisgiwyKanc/u8lv
         ETLA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728773388; x=1729378188; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=20NF4tqMkiBbTWgWiCl4WQg/jcaDcrbz1qUQrjzy/qw=;
        b=aNmuwUEgZWXBH7aoE72QgEeByFhcvTjEGj3MrvS5356eLob00vbzowXyz+22m9vzD9
         yABinSjWUV344IsPLAnhD70jw23k41PezvOn91ZSDRg0JYyAQluuSQYlUI+bW8E6clIP
         a4RHqLV8yD0mjSTdclbUvmahIrUdJuQX4kA6dK0FgwPfRFZLg2f4hGTq07e+ij18Elaj
         Yx33ZYFdSJnvgMev/auPllN5FLs/pG/O5vCo5S+deguoTUeOpAGLrYbEJoDa+C2GvVXS
         ypG0Nd0la9fFaI88HBSOjyqarIWQTb8d2bInDZ6LWwl2FFfEYKPO7lqiqNY3+V9EsF2i
         gRUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728773388; x=1729378188;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=20NF4tqMkiBbTWgWiCl4WQg/jcaDcrbz1qUQrjzy/qw=;
        b=VlGOthVM5HQ70xSDe0EUSaXJhHnK3SH3GB31RmpsBtw+Wr30D7IrlU0zFlL+p2skNO
         TsRDw/t2LSJC65l+LIhcejWGr9JVT1gYQ5nj2tbwAg6HzEOeXW51ZWRaS07kNWoGBaww
         0bDHTMnrUBHbMhBxQ2w8wmzQA5fERxE+WlOaavlGr1JdgAA9pEjlc06+SWPJ8ALp87Rg
         syVMMdzOo/v4eskxK/jzw24mRB22H9BjiPArohJD+8ncf31FmUffEaMNIMS8hcq8jgad
         Nj5SXvlpAdYlf/WkHqKZZ3afvu7T+UUOykclu8TWqwPZmZ4e0dhtOcc2SeFyc6Whb2cQ
         8uRA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVROaHpj99w9OkNLtEKgpMzEzu19jTUpThnZ6seslaoE5P0w13knw/IT13HqKsE4EZNTXCoFw==@lfdr.de
X-Gm-Message-State: AOJu0YwbIIST1rfPA4maLPcWVDZNT45ueM5b/+gsEcgMQCVuY1D5pwlB
	sdJc/xF2XBjGDjCzWVyyTAdE/4/oQ0cl25cUTR2IaAOO5Zn959M1
X-Google-Smtp-Source: AGHT+IH99IlaT3g2QF/OJM+7ZMVenkve3K43Lei2Ryh98Vc2e7nn4nd8BSiqkIISIkSU3stZPZ+Lyw==
X-Received: by 2002:a05:600c:1c9c:b0:42c:a8cb:6a5a with SMTP id 5b1f17b1804b1-431255df67amr37256715e9.15.1728773387388;
        Sat, 12 Oct 2024 15:49:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c28:b0:42c:c82f:e2f with SMTP id
 5b1f17b1804b1-43115fe01b7ls5212785e9.2.-pod-prod-05-eu; Sat, 12 Oct 2024
 15:49:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+ArAjKLNvm58TO+HbTMlrj4mD0bZQdTaQ5RQ7wniuJ6JWYVtjlcFL4o9dWlHpdCA8vuKE/lNRoqA=@googlegroups.com
X-Received: by 2002:a05:600c:444f:b0:42c:b62c:9f0d with SMTP id 5b1f17b1804b1-431255e03d0mr47293645e9.17.1728773385528;
        Sat, 12 Oct 2024 15:49:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728773385; cv=none;
        d=google.com; s=arc-20240605;
        b=dzzepr+B91fKNrjfC5RbrraD2MsLvk297Zw1yLPAYPqioBO5hflFFGNO/p/9uPme6Y
         AJh43rUC1YSbizAJokFuURFDCjYiHNMJ/G/6jst7DBNVl5kIZKw8g7vDtdxInn2j0JlC
         9z9nEnf5HKPXBd1pqRyDuolnL9K8SVZXi2Eu6/4VP+esjf+DJF4bvLjEaYDBd/6AYHdt
         3wwMfMqCHzIjEzd5eUokaRA/UqNpUuylZjXPWItad4mQRrIGBnT3JB38ho8sgY9LsoO5
         1b7s5bQ2KYYZuvOIpOcgVN4SjOrbU2zfRv23t1MXrWXon2VpSAmKcozsZMrdRZCM39Xv
         oBjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XiYmV1p7PV/Xl9HB+YzDHEFG1quC1dKoP9wDR4TCjTU=;
        fh=os+fvpsjJFyOCfQwOM5zLMaC/33wcw7+x20XFFm5Gzk=;
        b=Q+G+GGuG6uTEhLyz21SZuW1LRXwXsavzGm+n8ahQOb+CfuiVb6f5Pyk5JObwAMDw03
         w3TvHhhdcqXzMOT/g3HfN71UuMTfgIpOpuCWJm1KdmuwbCDi7d0KoCeatbb+UQKj1D01
         4PGD1bslloW+ef6oovXzxMq6rmD0rJ0jqtL/2IP5a2MbRcMkt7vccBRTscJOknB9QA/A
         PKGqARgr/AGJazdMtTTIBnKatFKkcaoQhQrpoZS85eXVIf9h0Isf1ay+k9pqM+5ZxqWj
         6D77IWDjwAx+B4yy92VTsvBpj+HlHltYASRYiVML1nhXWOZusHqK6xFfLa2CPwbBZX92
         /lCw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cVxLFQXk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x429.google.com (mail-wr1-x429.google.com. [2a00:1450:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4310c3bf494si3751515e9.1.2024.10.12.15.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Oct 2024 15:49:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429 as permitted sender) client-ip=2a00:1450:4864:20::429;
Received: by mail-wr1-x429.google.com with SMTP id ffacd0b85a97d-37d58377339so1776837f8f.1
        for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 15:49:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX1k98TLLvuD5eG1f2ImG5jQJ1cXmIRpJ2EspqomYa1/Q4A5uvHe0vFddzTF/2aHgsVybbi5WbJgds=@googlegroups.com
X-Received: by 2002:a5d:540a:0:b0:37d:47e0:45fb with SMTP id
 ffacd0b85a97d-37d5ff86f1dmr3202479f8f.21.1728773384724; Sat, 12 Oct 2024
 15:49:44 -0700 (PDT)
MIME-Version: 1.0
References: <20241011114537.35664-1-niharchaithanya@gmail.com>
In-Reply-To: <20241011114537.35664-1-niharchaithanya@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Oct 2024 00:49:33 +0200
Message-ID: <CA+fCnZd2yG9-bC=3nvDHLvkvz86x-4p0ewBoi4V5T40+BhQJWQ@mail.gmail.com>
Subject: Re: [PATCH v3] mm:kasan: fix sparse warnings: Should it be static?
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: ryabinin.a.a@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, skhan@linuxfoundation.org, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cVxLFQXk;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::429
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

On Fri, Oct 11, 2024 at 1:46=E2=80=AFPM Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> Yes, when making the global variables kasan_ptr_result and
> kasan_int_result as static volatile, the warnings are removed and
> the variable and assignments are retained, but when just static is
> used I understand that it might be optimized.

For future reference: please write commit messages in a way that is
readable standalone. I.e. without obscured references to the
discussions on the previous versions of the patch. It's fine to give
such references in itself, but you need to give enough context in the
commit message to make it understandable without looking up those
discussions.

>
> Add a fix making the global varaibles - static volatile, removing the
> warnings:
> mm/kasan/kasan_test.c:36:6: warning: symbol 'kasan_ptr_result' was not de=
clared. Should it be static?
> mm/kasan/kasan_test.c:37:5: warning: symbol 'kasan_int_result' was not de=
clared. Should it be static?
>
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202312261010.o0lRiI9b-lkp@i=
ntel.com/
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
> ---
> v1 -> v2: Used the aproach of making global variables static to resolve t=
he
> warnings instead of local declarations.
>
> v2 -> v3: Making the global variables static volatile to resolve the
> warnings.
>
> Link to v1: https://lore.kernel.org/all/20241011033604.266084-1-niharchai=
thanya@gmail.com/
> Link to v2: https://lore.kernel.org/all/20241011095259.17345-1-niharchait=
hanya@gmail.com/
>
>  mm/kasan/kasan_test_c.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..7884b46a1e71 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -45,8 +45,8 @@ static struct {
>   * Some tests use these global variables to store return values from fun=
ction
>   * calls that could otherwise be eliminated by the compiler as dead code=
.
>   */
> -void *kasan_ptr_result;
> -int kasan_int_result;
> +static volatile void *kasan_ptr_result;
> +static volatile int kasan_int_result;
>
>  /* Probe for console output: obtains test_status lines of interest. */
>  static void probe_console(void *ignore, const char *buf, size_t len)
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you for fixing this!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZd2yG9-bC%3D3nvDHLvkvz86x-4p0ewBoi4V5T40%2BBhQJWQ%40mail.=
gmail.com.
