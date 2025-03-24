Return-Path: <kasan-dev+bncBCNIZP7NQQIRBMM4Q27QMGQEMK6B3EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F999A6E041
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Mar 2025 17:54:11 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4768a1420b6sf80215751cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Mar 2025 09:54:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742835249; cv=pass;
        d=google.com; s=arc-20240605;
        b=EE4fcUB3+lNYDCSo922rIOU9S/nKX7oUfsi7wuCpQTw5oBuHjURUAbCpljr+rDelKf
         W6kuSg+kR0rj1ABFjIVaS4yLhgzGhBqmgM5fzX4AyKHuUtPWK0vdg5RNWj5fz6RwDt+z
         w/aO5c7YGj/5hCVbYE7Xt8lLBfZliGGOgxDkSI04qTKwqnyKXNOc0D8yFsIZ/kluOmn5
         CnORzH0Yj/JxtaB+8kZf6yACbdWf7evVwxswhR8tJTiiLGtFvcwmTqCsX+qXZMhUK6t1
         5ylVsvWDh+YUuLFh/zbbtrT6UpITR5dXP4l7X8iZFrRuoBL88XoZ30b89m0RQu9w6IXB
         y8oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=dJ4GN/tFt8JCDjnzLwtnhrpjJpM2rmEcRjsAp60C2CE=;
        fh=8G7UENIFHRl9kIgxTeTmtfeSbgHKqq+sP3u3XKj+l3s=;
        b=HKQvYcsEqprongyg1yR209ivOVl20BQfPnfDdrguFEuz2rQvTH8SpuYSCXjWDgov4c
         /MawwbD05jjtUkWIwkoRDAT0WpMtzehdNL+6Ku86InIQFHJuVcu7n5DlibfEX8A5PaMP
         u3ezUpLfj5BXy3NT/SQwnwktF9WOXw9q1kbSvfBycH8FA/OT9VlPaH1d+UTzbzMm9z1E
         elZDsLbWPZ1cWznrJbtO64w7bUeXQPMHn3NhDp8jJ+sahTtOjqaYoiYOZtN3Eg3Or3fx
         vXHRf1zRolaPCgMkid9rR5qceDfFLN8RwnUIVD8Y0I74pcHbAN5Gxg0LeURtnUd2/QOy
         i85A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QhOKekUI;
       spf=pass (google.com: domain of tony.luck@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=tony.luck@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742835249; x=1743440049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dJ4GN/tFt8JCDjnzLwtnhrpjJpM2rmEcRjsAp60C2CE=;
        b=P+5kYRZufk6IHRIWUxNPuuOEecC0Wl53E7+AQMD21pKrutyWIt1ntQaYD7r9N7YOOY
         ezODIu9zoNpJMkTqgdlICuAQgid+hrxMS8M08yfQH/fPUSP5mll6/1aXgROkf3v/fkFn
         ce2hdZi6Ix4+L4emqWcWZAimFCOr7r2VElUVJv9GeMeNCc+3Ag48EW0Kubh3bySjb1Cq
         +W3kPHCMeTZn8gO5tD49A6ev8VeLQFP90oF+IfnqcPO6pnzLODj8gmTKI+VFs6qAadow
         skjnAR2k/K7wnc+/knAhbPHmeUA1fiJF2Oi2R85nz7x66RhS27v+E3hTtwRpcMa4y9m3
         VkXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742835249; x=1743440049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dJ4GN/tFt8JCDjnzLwtnhrpjJpM2rmEcRjsAp60C2CE=;
        b=tFQCqBwPS0W6KQ03y0t0YZtQD/EUEf7/s4/NAMl0Z+0QJsUUuYbjFRlGSJywtBuamG
         HChSrDsohXPehS3h4i5f1caMUzc2/C/nffWhfPGU38txIzq+jvGCSPQi17hYz6tMlGxC
         4vvuXkZ2AaQbwBz4GZ2yUgY2KCBIjTs6iAHRV667M7o84qwmM347kEYCeTquhnHHuVie
         hCWi8Ei/um9y5sgPRkfJP1Zw3TaeXMYpSlBydkdRFQzjxMB+l01nJrP624O6EV+XExe4
         mP1H2OHkBA/PvXRWlp7aQXesVew9kufUocRzRnqGvxBACVnVa4+yM4453QtCLFqvu5Zp
         RvHA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAXcyFfSZlcmZRPqLkrbv+XoOwkyhKjlByVExlusOQ5iK7lhW1LeDQolL+sIkOfaLxK1G1xw==@lfdr.de
X-Gm-Message-State: AOJu0YxbpK65xl2mDg7ZlADjbHhLVSXsuv784r2n2YzIOiT+PHHzy6FG
	ZgmbQ6I+mB/0GrlIkwGb3tiWcRGX/0IztmyAy93baeu8RbzT1Zf5
X-Google-Smtp-Source: AGHT+IEHZPatsAsbw9fZKMsvdST4Ulzwg6JnbcH4Ge9TaPQazjxh9qYuDmNvX4je5yWgCwit/yCLIw==
X-Received: by 2002:a05:622a:1b27:b0:476:7669:b947 with SMTP id d75a77b69052e-4771de15a18mr194155521cf.36.1742835249349;
        Mon, 24 Mar 2025 09:54:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIlKbpcbtS8rWul4+GROMeBDhCKOrsNFA6DzQ/To35Ldg==
Received: by 2002:a05:622a:1907:b0:476:7e35:1ce7 with SMTP id
 d75a77b69052e-477109a9e05ls13634511cf.0.-pod-prod-03-us; Mon, 24 Mar 2025
 09:54:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWYKIgGgOJ3uswXOWFrTJkdUpX0UxJUUFQN41GnlseOIYj10mmUDm0qtq6x/dDgQvJozkGrwbqBJQY=@googlegroups.com
X-Received: by 2002:a05:622a:5c92:b0:476:a967:b242 with SMTP id d75a77b69052e-4771dd9bf77mr234390511cf.30.1742835247318;
        Mon, 24 Mar 2025 09:54:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742835247; cv=none;
        d=google.com; s=arc-20240605;
        b=HSG7C2XlboCLEyZWj4x5Sm9OgqchqVd9rqSvF6w73VLg7Y4blEXfPmnSCTFWVquxRX
         Vf0pzTbiGe0qDRHcipaRKrgiG8ccHu8sS/+9fFjYRwFePURe2cXIPuLeX05Zbt0+8j7n
         OBq/7mZxw1nzAn6ly3Y9vveNhkRIcEh4C3k3im/TNns6K2iE99NhCyt9YiRXk7da7Mzv
         0qFpLWrt2FjCNpAyaAV1NBm2+aspSoIPHYFlb3ulkut0Tfd8UOEEGXY17PWYTSTAEirI
         cHXD9vUdxEOscSuvTFol7T04aaSVWyTcOZ6IH2uI/iUJVv3UWkOE+e/XEykm1WS39rbg
         a/HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=pCacE+xisYPcsgdv3+TM1VMm0lKFuw1VC2E+x/ru66M=;
        fh=VUNyIGxM6SFtZDgX9u7LXaBoQFdUaf1o3coVzqLUt1I=;
        b=TU+v2aHqadAFM/pTK6VoTJvkP9WWjphippTd7T1Q/YNevsydedKo6lDxuG1YhLWDvN
         uzU4bo1xaq3k2Oabdas9TUweDUJFCP0XRsLppHefDIuJB7z+G95Z1UPJ/mTT/eQOHsCV
         bWD2iZfCfnSyuuos2bEkLwYpOd9sTWvsQiuW4dmdh76Hqx1p5nANh4GqhG1+VfhIKh9j
         YWefQj5REAmHUUHfTVe1Btd9EMA0ABGdnuhw+vhzNmjc5odO1wmGzaB+BlEausqgI455
         HjESfVInByPCpgjhu+h4dttUKTBXo0/zHrzyxCG8Ad78NibA7o+jKkfInHX+jXNhFYR8
         zpOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=QhOKekUI;
       spf=pass (google.com: domain of tony.luck@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=tony.luck@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4771d1be3b1si3706821cf.5.2025.03.24.09.54.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Mar 2025 09:54:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of tony.luck@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: x8J9jusWTaiEwgJ9iYav/w==
X-CSE-MsgGUID: mNWJxoe0TDymxW5FXEfHnQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11383"; a="61444870"
X-IronPort-AV: E=Sophos;i="6.14,272,1736841600"; 
   d="scan'208";a="61444870"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Mar 2025 09:54:04 -0700
X-CSE-ConnectionGUID: y2R8TjF9T0uyVt27GhllBQ==
X-CSE-MsgGUID: cDQOi4IQR9e/FuSVLgSLxw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.14,272,1736841600"; 
   d="scan'208";a="124891128"
Received: from agluck-desk3.sc.intel.com (HELO agluck-desk3) ([172.25.222.70])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 24 Mar 2025 09:54:05 -0700
Date: Mon, 24 Mar 2025 09:54:02 -0700
From: "Luck, Tony" <tony.luck@intel.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v13 2/5] arm64: add support for ARCH_HAS_COPY_MC
Message-ID: <Z-GOKgBNxKWQ21w4@agluck-desk3>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-3-tongtiangen@huawei.com>
 <Z6zKfvxKnRlyNzkX@arm.com>
 <df40840d-e860-397d-60bd-02f4b2d0b433@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <df40840d-e860-397d-60bd-02f4b2d0b433@huawei.com>
X-Original-Sender: tony.luck@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=QhOKekUI;       spf=pass
 (google.com: domain of tony.luck@intel.com designates 198.175.65.10 as
 permitted sender) smtp.mailfrom=tony.luck@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

On Fri, Feb 14, 2025 at 09:44:02AM +0800, Tong Tiangen wrote:
>=20
>=20
> =E5=9C=A8 2025/2/13 0:21, Catalin Marinas =E5=86=99=E9=81=93:
> > (catching up with old threads)
> >=20
> > On Mon, Dec 09, 2024 at 10:42:54AM +0800, Tong Tiangen wrote:
> > > For the arm64 kernel, when it processes hardware memory errors for
> > > synchronize notifications(do_sea()), if the errors is consumed within=
 the
> > > kernel, the current processing is panic. However, it is not optimal.
> > >=20
> > > Take copy_from/to_user for example, If ld* triggers a memory error, e=
ven in
> > > kernel mode, only the associated process is affected. Killing the use=
r
> > > process and isolating the corrupt page is a better choice.
> >=20
> > I agree that killing the user process and isolating the page is a bette=
r
> > choice but I don't see how the latter happens after this patch. Which
> > page would be isolated?
>=20
> The SEA is triggered when the page with hardware error is read. After
> that, the page is isolated in memory_failure() (mf). The processing of
> mf is mentioned in the comments of do_sea().
>=20
> /*
>  * APEI claimed this as a firmware-first notification.
>  * Some processing deferred to task_work before ret_to_user().
>  */
>=20
> Some processing include mf.
>=20
> >=20
> > > Add new fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR to identify insn
> > > that can recover from memory errors triggered by access to kernel mem=
ory,
> > > and this fixup type is used in __arch_copy_to_user(), This make the r=
egular
> > > copy_to_user() will handle kernel memory errors.
> >=20
> > Is the assumption that the error on accessing kernel memory is
> > transient? There's no way to isolate the kernel page and also no point
> > in isolating the destination page either.
>=20
> Yes, it's transient, the kernel page in mf can't be isolated, the
> transient access (ld) of this kernel page is currently expected to kill
> the user-mode process to avoid error spread.
>=20
>=20
> The SEA processes synchronization errors. Only hardware errors on the
> source page can be detected (Through synchronous ld insn) and processed.
> The destination page cannot be processed.

I've considered the copy_to_user() case as only partially fixable. There
are lots of cases to consider:

1) Many places where drivers copy to user in ioctl(2) calls.=20
   Killing the application solves the immediate problem, but if
   the problem with kernel memory is not transient, then you
   may run into it again.

2) Copy from Linux page cache to user for a read(2) system call.
   This one is a candidate for recovery. Might need help from the
   file system code. If the kernel page is a clean copy of data in
   the file system, then drop this page and re-read from storage
   into a new page. Then resume the copy_to_user().
   If the page is modified, then need some file system action to
   somehow mark this range of addresses in the file as lost forever.
   First step in tackling this case is identifying that the source
   address is a page cache page.

3) Probably many other places where the kernel copies to user for
   other system calls. Would need to look at these on a case by case
   basis. Likely most have the same issue as ioctl(2) above.

-Tony

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
-GOKgBNxKWQ21w4%40agluck-desk3.
