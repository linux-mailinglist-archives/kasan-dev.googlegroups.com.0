Return-Path: <kasan-dev+bncBDW2JDUY5AORBQ7F6XCAMGQE2OTR7LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 61084B25AC8
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 07:23:17 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-55ce521d3ecsf237382e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 22:23:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755148996; cv=pass;
        d=google.com; s=arc-20240605;
        b=RLWz3ep5isJLvnEgH2YWSPAk5b4ui3mX+HYUImvibXPVDsHmbZkcCB8edfspxPZnJv
         M9fSiD064ghGFhPPKfY1n9tUsDgymVpoH1hzOxJzKdlXUTldLD8CJIhrRbn3nHkEaaH+
         gfM4tk5JW91XAZheTUYPcRGWrM0ID38loNEJ4mgJkpnGUznfIAgwPqYZNSI3RCAjlPfT
         08DpB64OS8FZG1q6u/y9TvcP4qJSzfZh5QmunrtwlrnKrzZRAx/qAFq9IEb5/BeZh08h
         EcnoRHMnFYX3Hom6mSYzBhSem/1+UDYGG4O5sCzxgVIb87mYunlyTxexlr79YHGpksP4
         P1fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=5IZD2w0Kn23Xvs93GFapXdkAZdjIGrSyziBubiibOfQ=;
        fh=RG3Z48SgW4n8Z4IAJ7kTA9ZkXFuL52YhMLIEkKzWkZk=;
        b=aWo7cn47bfsrIo1/oaNJoH/4tPrXgEaiMXAI5zyGKz0Yrd5751Cx8mY8NzJtYGPK67
         AbphcyLhp+Hdx5zV/kAiOasJEZGze85fdSn03hHLrzSPvxq5gEG4My5wy8rWkkUI0MRf
         /etLegscupugRLtUxrDJrscmYlOc1hUrb6/vD/K/j43lYARPJk6dauTj/4nAcXIapDtN
         msUhbxXDC0yfxLhYUvcr0EHgmLduFxBGdvfIa879SfhTa/TvjuuYLmaDFmMscZc1GMZ8
         oZdJWIyvHa5pq8TCbZTxbgF+1Z7ZiN5D59eRZC+tXCf4t8adqKVsfxIyv7mZHEzzOsL4
         JAww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="W2a8/06o";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755148996; x=1755753796; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5IZD2w0Kn23Xvs93GFapXdkAZdjIGrSyziBubiibOfQ=;
        b=seTnYhemLh+QA0n3LmKz+fM18SIFw/Y49lY6BWh7ksVARoezZ1ZfOVdd0jEf8i1dTL
         6H84VHGpYL80cY5MWXxr9yw8EvVrKm9hTy0U++LtpMJ84inmChtZBtjiAZfFvEBVtyur
         kC7ryRB4g0DA4n2cD3iE7+lLMBtVm7Qrct1dGUQ7g3XC+qiVyf+sJMBLn9Z+GTRfbpgk
         b/Z+im14EJaZKI6P25ZYAfgIS70tSyJxcQw69UWDSYLRvcNdfdXIljJHZnu0T/7SY+3y
         8HCJW6O5jsjsgfIjtm6Z7514TtoiEsbpW6nedAu7OouCqUCCflGyiXtARcDlmf387/nP
         GYzQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755148996; x=1755753796; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5IZD2w0Kn23Xvs93GFapXdkAZdjIGrSyziBubiibOfQ=;
        b=cX0P64eU8GOdb0c4kQ+pjqRamQMVzM094DVADiroJjP/hf9i1EAyZLO6Erec6nJCAb
         745XIh7x4RKPYAkgTV4WExyCLBL0cAYPBruzWHUMhBBIck+Ffh9VIBJVSeXgMJ46UEqD
         eE4YHSIFCsSU6LoCq8GxUrNIzcXCz1/x1us/y4mAGNY4Ayg3GgOuzK0PLYVN0ZXKAXOD
         vyIp8+E70T9QVYIv9XLlmrQiJr6F1L4mDsPSxJxAiUb7FxFI4MFoOGXH+sPvD1gUq5Lg
         ZqRPNo8dfWUKU7gUe77dOtrf/AGQZpF7P6OXRK3IWiXDOMUPgi5tpkGm0q/0iTVbuEKR
         3Qhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755148996; x=1755753796;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5IZD2w0Kn23Xvs93GFapXdkAZdjIGrSyziBubiibOfQ=;
        b=awtyUSLkA7h0pWKSmSvzFYnOJU01rSWCN7EGtyt8HuOImG9weCCBoa34LfxfTDQ7JD
         XsC54SNV4FxjINvPK3CJdXQ0p+IV1iFMRSormcrWFcs6LS+BXtoEM7YghGof2TekO9df
         hjwgGqUG0JxvKtBBCbQnSG0paHSOmQ4C+qO3k/QmPqf0dbTtL+VTCw4QCXEIgirXkSis
         8+Sgj4mo4aufIzGj1mh21VVQtb8V8N0O68wz2Mx+N9yrlIIVmE3/7GeCi7wa1/u5I5iz
         tP/Dolpk1w1YPhzWRtQuLcJYss3wxI+1rgMpIp/cYNDgCCyqfopIxa17RjkRmZpHNltM
         zJRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyWRf4neM4jXGIckmFG7FNkpOz00rBkwK5N1GTXVpGiLQtmndpfgVRr3tj56DkjBy9V9aYGw==@lfdr.de
X-Gm-Message-State: AOJu0YwNjC1XW7xjhfX8dOMh9yulk6QkbxKovWU9uzsT9nsMYzYpV6GN
	fGRYu8V2s+FRzKCfM3MBWKG7u0GqYrnmOk08JAePT51fGylgCXUIZnBH
X-Google-Smtp-Source: AGHT+IEeR25SkUWDxe4YRHvm3oUh82/Nz7s/z+7/GKvFyS+S/KCeC2WQxeGw1Uv9shLfykacLvsBiQ==
X-Received: by 2002:a05:6512:318e:b0:55b:9444:b15a with SMTP id 2adb3069b0e04-55ce4fe6d20mr533112e87.20.1755148996028;
        Wed, 13 Aug 2025 22:23:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf+fgQ3DnFDJRiKum5GOH8M54kUgTRS4Gu/U+0C3TGwcw==
Received: by 2002:a05:6512:3683:b0:55c:e528:4c7e with SMTP id
 2adb3069b0e04-55ce5284d9dls116579e87.2.-pod-prod-02-eu; Wed, 13 Aug 2025
 22:23:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/Z8I5B20o8HKp/kjhbjsDwvMPJ2x6Zof5M/z7WsaecbT63MD/5Ig2ZWyIw6hxyB+JaUophE5beY0=@googlegroups.com
X-Received: by 2002:a05:6512:138c:b0:55b:8971:2027 with SMTP id 2adb3069b0e04-55ce501aa86mr591111e87.36.1755148993157;
        Wed, 13 Aug 2025 22:23:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755148993; cv=none;
        d=google.com; s=arc-20240605;
        b=Jb2O46DyqfX3Zlui1Dchwar8hg4dAMKDT1PQ96egiN7uueHY8Plk57t6vS/Qdqo0ut
         1ZOmj4Y0F479WtGhfNOEVYdhP1DkMCaFLKLDUe1wZ19gXuxu0NwmPfj40CeaoJcN7l7E
         1LmqI2EoILN3bzZvVuhOn2f1l3y/nsLRYYW+Yypd3N261LDl/VaHOaWTeyGs2aN1XaUs
         5dZmUowBsxS4yeNQSHekFW7lLwhuD/cC8o+vM0OmEUYKPJPVtx9Yt9yOXSIahYFvtYXN
         IB9KTwHznztkcf6p5CKLw3uAyk1SODlO6xcCl/rZhR8Dwt+Hz4X4v31K1Yv3mS3b+ywa
         RPLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3LSoCl56fyWME0v8PiSkctUuL3gtGDTjl3bz0icHfT8=;
        fh=ciIuX/xk1ufgX2bJQsd4vu0R8FZwa2p/5ptJApyx1cI=;
        b=V8hU7emjj/PI+HzlpN5UpnLVOo3BZGo569bgDecmlK+UsgBPXwSuowEWl5tJkmSHuI
         mXJqtPQr6m/3cgt+cY1XmJr6XJpAtobRpahnvsnLe/2un1XMBkXCWdYeCWJTyj2qv4Ri
         QWBHvAWDaxg5A6XNIqMW13BHQyPz0zQBn1hX8r/XnuYonRtfTT8yK7UYc+0Zay7S/Rgt
         6Ws6CnRET4NXicBailc0UKIygJkVITu2+RzjYV7NuycCmSlMEDu6KVdeWORqt9rBYg+u
         5qdhCRnmg6c7tLEWohGsq/8lDqwQf5JvIa8UHQ50xoUn3PEMWpQBU+c2zeHM8mQ4Heki
         3GxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="W2a8/06o";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b8895a3edsi637147e87.6.2025.08.13.22.23.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 22:23:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-3b9edf4cf6cso334793f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 13 Aug 2025 22:23:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUD7TTxm0aFRZcvQV3wjkITZeRoxZOY1nxY+QZSGJuqK0EefMl5ZkmvAq2ZJWlbK81lqN7dSjA+YgI=@googlegroups.com
X-Gm-Gg: ASbGncv/eJU6SpUaytsmtPgawc7i1SPyj1uerkAntKzaHlqrTHLbcmEYKhSy28h0v1P
	K/YbU8KzxjvNz2GtHcegMdcbgtnHQTKkwXe5IMuZOPDSt086o0hen+k5B7LMTkSbg+4nUG1FDxS
	J2cti24c5R2XjgTuPXmwJwBVC8YRJTOvdKN7nt6DmGUwTJk6an8ESHPX6OLHc7wtyJi6TPkqbnH
	Ipqoxcbeg==
X-Received: by 2002:a5d:5d88:0:b0:3b6:8acb:a9d2 with SMTP id
 ffacd0b85a97d-3b9edfcd141mr1235453f8f.7.1755148992352; Wed, 13 Aug 2025
 22:23:12 -0700 (PDT)
MIME-Version: 1.0
References: <20250812124941.69508-1-bhe@redhat.com> <CA+fCnZcAa62uXqnUwxFmDYh1xPqKBOQqOT55kU8iY_pgQg2+NA@mail.gmail.com>
 <CA+fCnZdKy-AQr+L3w=gfaw9EnFvKd0Gz4LtAZciYDP_SiWrL2A@mail.gmail.com> <aJxzehJYKez5Q1v2@MiWiFi-R3L-srv>
In-Reply-To: <aJxzehJYKez5Q1v2@MiWiFi-R3L-srv>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 14 Aug 2025 07:23:01 +0200
X-Gm-Features: Ac12FXxjjLGYLRyCaqd7TSTNKQmFZtITu9sph-q46cifbE2W4uXByRYl8-gsmGA
Message-ID: <CA+fCnZfv9sbHuRVy8G9QdbKaaeO-Vguf7b2Atc5WXEs+uJx0YQ@mail.gmail.com>
Subject: Re: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	elver@google.com, snovitoll@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="W2a8/06o";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432
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

On Wed, Aug 13, 2025 at 1:14=E2=80=AFPM 'Baoquan He' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> > I'm not familiar with the internals of kdump, but would it be
> > possible/reasonable to teach kdump to ignore the KASAN shadow region?
>
> Yes, we can teach kdump to do that. Then people may hate those conditiona=
l
> check "if (is_kdump_kernel())" being added in kasan code. E.g even
> though we skip kasan_init(), we still need to check is_kdump_kernel()
> in kasan_populate_vmalloc(), right?
>
> Combined with the existing kasan_arch_is_ready(), it will make kasan code
> ugly. I planned to add kasan_enabled() via static key
> kasan_flag_enabled, then it can also easily remove kasan_arch_is_ready()
> cleanly.

What I had in mind was something different: into the kdump code, we
add a check whether the region of memory it's trying to dump is the
KASAN shadow, and make kdump not to dump this region.

Would this work? Would this help with the issue you have?

(I assume the problem is with the virtual region that is the shadow
memory, as kdump would dump all RAM either way? If not, please clarify
what how does the "heavy burden" that the shadow memory causes
manifests.)

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfv9sbHuRVy8G9QdbKaaeO-Vguf7b2Atc5WXEs%2BuJx0YQ%40mail.gmail.com.
