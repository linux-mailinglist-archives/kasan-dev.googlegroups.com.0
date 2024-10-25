Return-Path: <kasan-dev+bncBDW2JDUY5AORB644564AMGQEYCJ5NRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 215419B0A74
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Oct 2024 18:59:41 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-37d67fe93c6sf1163637f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Oct 2024 09:59:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729875580; cv=pass;
        d=google.com; s=arc-20240605;
        b=R8/AKZiYz+v/+ZUsjSsUxo0teP1J7Gf86UxWEuGRMciSwrl72Iw44oFLNdCMTxwLFX
         xvsgx24jFOxRdTq1Vd9esJLbS/9aZ7bhM2dwmuSdM11J1W4XdWhSqOJNAboJXgUGgmde
         /D/xtfYBBd36m6Y0DpbrpSOv/x0XNLvg+VxxWPcGR02tnub8sdbvZyFpNC5UhZbx58mA
         PhVDzZ4f2ZSbAhZWECzh3xA8H0/5O99PupOZMPcyJxrIerw9da00mvhj2fHYt6IVc1f/
         LBEJc2m0lp/qRIJdyxH/mstiegBaVB+Bq/D2dr8v6basQNhzecp6zwOGBLGTBTrdAA3M
         mK/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=dhgBkAjYIKY0JeYiH+KfA7odz4waXWJtbaX21oMIShg=;
        fh=a12tS33x+salva3j2qNGJMkTWLN8XKzfVPSrziBCwvs=;
        b=HNfCcsQvBBrZn++SHrqOoEfq4dYPGDKuaTseqGF56l1ZgCUNNJIETqrapVZ2Gv9RF+
         iCUSaDu19cTdEt+eVWnRW86rhU+mW4aUqS/oq1XePpCySyd8daV8xTjCmSMFXVY1vrHe
         6nWmLyRNoQDbqXMG1+ezGeVnD4WTFidn69JA6qAyVpRl9MzqKdWhSan8axT04bsovLqk
         x5R5RCu7hQA9wdwHd89C/T+h58JKRUXiQzP7A1DPLVLbtxTdcOdGOdmOdk/ss1ItiFh5
         XYWm7PGa4S2PGYyLf4nXfDv54XTQIJZtgVQ+b8OnSp60HcT3UbkBmnA8bkO4rmKKiMBo
         xCnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VMRPP6Fs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729875580; x=1730480380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dhgBkAjYIKY0JeYiH+KfA7odz4waXWJtbaX21oMIShg=;
        b=QT0KEW/XYuddM5oyRnredhIVaTuoRconDefKKUFoY+lXMj+HfbgSZkVfwuimttOFu+
         Eu0B4S6mZ5blGbXWaZgiCTkhj7vNHnH6MeFcx4YvpOVj1XqPi8IX4KJV6yTU1PkebFy7
         4IxE+YauF0pXyAudWp1KWv9h3HMP7pbf/NHhQmeAglRINQTKmVp11PuHQdSqm8ETXtkX
         t1s4EoUdM/cOS2Ys0uv7T9ggOykkZpDQBbCdbYYH6e/qqdmyTgIyP+1GUXWEyaOWuNgV
         8KIzE5cxUVoGm4dRUgWOxQP7mu8Hq9hjBiTIaPirygt7jsdVyIUlCWRv5tX2odxAd2NX
         /hDw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729875580; x=1730480380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dhgBkAjYIKY0JeYiH+KfA7odz4waXWJtbaX21oMIShg=;
        b=agpRrXXdfdWD1v+gR7EDH6HYD/kb++/2ZEqai6vfoA7Qe0unDNL0aX1B354AY6aROp
         bdjcvk6ExFmRW5d7W9TpxhHl6dyK2sqhWe2Z22xuk+Z6JWMld5mYz1NiN11SVxVWMzqu
         x80tdA3CIx/OpjQ8dgyFMBkbu96joupEmvnXYdjsjF9f4BN9DIF/6+slqno0yHm6aWoY
         LTKfQEdlo5j2kJMm9zJFi6JeZpZzPuueI0eki/I5JAhoHoZ7WPtdzzLEbLKNHcnS+0ud
         eFSTVUuVZLetkymTLfTF8IhRGt0n7BpgZj0QDEcT8rsmpjjvUFKPkXCSxNjpbuog7CHY
         BCVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729875580; x=1730480380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dhgBkAjYIKY0JeYiH+KfA7odz4waXWJtbaX21oMIShg=;
        b=Dquj/O9ThJgy4UKR74allo/EowV7pYY6p6MjAcPCKLCohQL1Rq/X0qXO/CiBcAdMrH
         DoY7VsTftSF/xM9R3CnSRqlVb5Hf18fgbzjCQlLGhOtJM28IaQzgooWYb9O8QcCN4Qis
         T37wyz/PWOGM36oi/sQY0rYFDaMmFj92FQUeeOS2jrp5k5kYauBQ7q5T8pM4PkDCV/Ig
         Yq+4uXEdoz6uKE/BH9w+2Fk3XhsEME2LOSKHkrkEOW5I8+8+mhf5KNqLnD12+83Bk7zo
         uSup1k/62NOhsUFqpA6Sd2O2AyPn/dcf2z0Y2zJthC/2GTVpH7Mu6QlTGgYxsmeZ3PvF
         GsJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrrBwlCKy+XLivq0EV7R5KbI9N5XNnxIa3rIGNhTBhMwpbWInPMIvzQVeDlE1RA1z6Jh+1EQ==@lfdr.de
X-Gm-Message-State: AOJu0YyR5wwrwhd3i3ZxsJwvrQq2HV86DHFaQT9FW39+zOtRYzR9yL3t
	y6W91Bi71pILw8U21P2U9PtsimIEh2K3irlJuy/ZNj1cfyicM0Zy
X-Google-Smtp-Source: AGHT+IFhOgMZ7hYc09Nf9YXua1YlChXmlEdkaBir3bikGLqB57WFW5A72nne3wnWrmQKIu1nSLCxgQ==
X-Received: by 2002:a05:6000:d81:b0:37e:d719:89d3 with SMTP id ffacd0b85a97d-3806120ce7fmr59559f8f.51.1729875579808;
        Fri, 25 Oct 2024 09:59:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:414d:0:b0:368:31b2:9e93 with SMTP id ffacd0b85a97d-37f598ff395ls562155f8f.1.-pod-prod-02-eu;
 Fri, 25 Oct 2024 09:59:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXk1B/xeH+iI/qbr5YP48HkOOkl0wxTnXaGDTAZWLRtglfb65cAs/NpvEHLg8opLACWT7h6Sqcrj3I=@googlegroups.com
X-Received: by 2002:a5d:4311:0:b0:37d:4f1b:35a with SMTP id ffacd0b85a97d-3806110b864mr78199f8f.3.1729875578040;
        Fri, 25 Oct 2024 09:59:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729875578; cv=none;
        d=google.com; s=arc-20240605;
        b=jTOSl294FiDLKZkco44RkezRh156C5FcShPFK3bBxnMreckNyn3doPocx/lA1ER4iZ
         VwfqIoPnHNP3BCNZYtEP/UKVBiItLhve/NNSrPcYSb7hDyZQUWVQRV/qTsPmUI+rPCcm
         CL/QNOf2ZB0g46LvpvX4IKWOHcJd16o7GcRQqPvhM5jXflwIwPIShhoe6T6yLRLe2ONZ
         JA+SWbBJ7HiOLZ69N/Yvfw8JcVxjq+Rp5DmlKT8MOZsdfpnIiS75N+MXUjha8isw7EkJ
         NLbTiwOyxZR75ILC4zjkaz/I+od7T4IFqlU9FV9IjRmNH+bgowfgkHDVpq8hSCEuCPBA
         6w/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9B2cVTHJK0N8Rua3Nes4Pd7LPA0lRXUOHcZHyL1EAuU=;
        fh=c4O4A/3Q5XJKAqN5zZCeG0coYUTQ18/kwZa8iaVpb94=;
        b=ZNM8Di1GTSAPTtnSRXWfUZcTlam/rPutrnmMEyG4om36GgF0PEccwql/M8tTZkAOlZ
         RrP4eRLzyy+KRkC7w90jNukqc5agUWIcXikfIkuCwUNhtg8Y9gjbOojIU45OCp8Hqg8f
         ndVb7WJFRselWFbeKF1y/jgVZ0H3CKpAkidU/8szQ7pswbZcvL8LfUyQSoL87dRyGiVr
         BsD9fHCVuKnY5K9ND6bggOn4PJShb3PzN0+9aX8GpHThaVd8inE2ZdlN2OfNS2nlbKQr
         K9d6q2IQP21kv9nEg1UJM0gWQ2Kc6SUv8usW6s9pfKwSsSZtnLi5sOW4gY4uYMjI6pQy
         nSPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VMRPP6Fs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38058b478cesi33604f8f.1.2024.10.25.09.59.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Oct 2024 09:59:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-4314c4cb752so22184805e9.2
        for <kasan-dev@googlegroups.com>; Fri, 25 Oct 2024 09:59:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUbx4BdFmKrr3+HXApZZRSm8VGOCY3cOG89NWyb/tJsVv3Lfo1VXcQXJ6W2nDqwFFKo2P4nh/3T6PM=@googlegroups.com
X-Received: by 2002:adf:f650:0:b0:37d:4e9d:34d1 with SMTP id
 ffacd0b85a97d-380611eea37mr70919f8f.37.1729875577264; Fri, 25 Oct 2024
 09:59:37 -0700 (PDT)
MIME-Version: 1.0
References: <20241021195714.50473-1-niharchaithanya@gmail.com>
 <CA+fCnZf7sX2-H_jRMcJhiYxYZ=5f5oQ7iO__pQnjEXDLUS+fkg@mail.gmail.com> <f26691b2-fe26-4e13-a34f-c4a2a995f25f@gmail.com>
In-Reply-To: <f26691b2-fe26-4e13-a34f-c4a2a995f25f@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 25 Oct 2024 18:59:26 +0200
Message-ID: <CA+fCnZenG-jQqXigPDOrxrnfzXnuirLOigvCWOCoXu=5Wp12EA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan:report: filter out kasan related stack entries
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: elver@google.com, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, skhan@linuxfoundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VMRPP6Fs;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
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

On Fri, Oct 25, 2024 at 4:48=E2=80=AFAM Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> When I included ip-based skipping for filtering access stack trace the
> output was
> inconsistent where the Freed track was not fully printed and it also
> triggered
> the following warning a few times:
>
> [    6.467470][ T4653] Freed by task 511183648:
> [    6.467792][ T4653] ------------[ cut here ]------------
> [    6.468194][ T4653] pool index 100479 out of bounds (466) for stack
> id ffff8880
> [    6.468862][ T4653] WARNING: CPU: 1 PID: 4653 at lib/stackdepot.c:452
> depot_fetch_stack+0x86/0xb0
>
> This was not present when using pattern based skipping. Does modifying
> access
> stack trace when using sanitize_stack_entries() modify the free and
> alloc tracks
> as well? In that case shall we just use pattern based skipping.

To clarify once again: we only want the ip-based filtering for the
access stack trace (the one printed directly from print_report()). For
Allocated/Freed stack traces, we want to use the pattern-based
filtering.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZenG-jQqXigPDOrxrnfzXnuirLOigvCWOCoXu%3D5Wp12EA%40mail.gmail.com.
