Return-Path: <kasan-dev+bncBD4NDKWHQYDRB6U2QGWQMGQEIL3CEXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4164C82B5C6
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 21:20:12 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-40d8586c709sf52028225e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Jan 2024 12:20:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705004411; cv=pass;
        d=google.com; s=arc-20160816;
        b=Frv7FiXQ6xR2A741mu1eQiLCFSDLgA5EuVOGG5ZttCY6Z4ZKD3tX4iSlyVJsX9Nw0h
         aW7h6ObcY7XAnT6UmuODxnN9beLAVz+5FxzpKVc3wlM+pP9g0La+dKG6qfiAapCCuic/
         cB8SrbV2UXPUoKGcfLcQ7CJLp6ZBLK5URtzQBMwacm3eBJzey5z+DcJ79QLYqsr9aU+y
         QCl+FqcJncVITl2bL2wK/tBMLxl6H7A/yKlFFHb/AUXHbjDr3JMQ+m4g7t8y/CwKlRhX
         Ahe/mIujcw3UtlZibGs/FLptxARJEBJ6cfxerrJhexBU3qawQpf2sT3QLgpRbdIyDFLp
         hvug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=E4Qise0/ychMeKJN+ryAJh7mlrIoOqhWQGRXkts+Fx0=;
        fh=w9eXdKbGWqwMoAi9ZO7gDLjQxF/4EBZnS+jKng4X7hE=;
        b=WloI+0xCxKm/eGh7AvEkLav9cV4rbucaTj80bNp6zSwTAwDXQROmjfcQ2bwah+x86D
         BKmh6gr8BVzBM6iUd8wyNgxRvx3m62ZfVvvD8nUuT7RF5AuFMWXbJqtSPRRIcGiR2PNQ
         gUV1mdqZ2tfPX6Tutcdg7wCH+4O2CkJu04sHZLb3+bxD56Zyoy5blDE6xTkubPqFcgDX
         mklIhSCiWsNeKW6BgNci0rPfWp6/7wjnUGqpyi7v4YWkKW793XvO8gxKW4Cu/HRiYPft
         TP3wVGTFRJIIiE6vOOzprtbrTNuwzVUDz59Yg3LeBzLdH75JkcC6I7AJSfFPldXwX3aH
         wEdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Pz76U6jP;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705004411; x=1705609211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E4Qise0/ychMeKJN+ryAJh7mlrIoOqhWQGRXkts+Fx0=;
        b=eOTox+HZsg4zkaHECZFZIraILOLpb2ARp5mOOM7fzAKZHaGuo7feZaf5tBfEtqqseW
         ZYlds8zpHqvr7SHO70roBBBnuZlTlDVNvP94d74KsFHK3K6NFnvDZLJyeFs5+Qs8w90p
         6tHIrHXi3YgrqbAPwQ84ZsCVHoPkVr/90NMLpicq5NlPEE7BL1O+0nz/t4bypJIv1JU6
         pdmR7GQywhgbcgvH9/mzav32IzbdHYoVBNXXz8us6zTWChon1JPTjcUFg4cjoBT1eYBh
         VYKBInGh4P7vmBs6ZYNCjqnb3T5d9ARUWgKwoUMb19R9jpcylaaRonQgE++3RyXzXjDr
         pzTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705004411; x=1705609211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=E4Qise0/ychMeKJN+ryAJh7mlrIoOqhWQGRXkts+Fx0=;
        b=WharKX0xIOxfOoM3kLTJJK8ISzm9rSM3PVVDemAFHvOhWfHAdTKhGUcxT1gd6Bsr/z
         2VJA5aFzfztDSrkAW9QlndV9dQSTtWIQqYHn6MBWToMQOXlxCOLlp+IxXKB5sEJ+uO+g
         QeBhX5oDJrgTmaLa2b/JqvBQR534SrRQN0OU7yCOJPE1cMfN//t6n2Sl6RQiuKP53wGv
         kG5pb2ThlzxUknI6q/MhqUIFq7mSQYez9SSmrMMfmfeK2Rnw8Ual7sAdKN3efKkcTIUb
         MBTkQoi5HSl8Xt3njPkgm8NVhSG1nI/dOkT81gM0IPheogJwRJs0hUxBchsltwPUcja6
         Vifg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxy3A+BBINMU89Dz4V7Rq/SaSQel9EmhqvkslAqV8y1uiLCDbgK
	yHHA+INHOkXnVC5oWy9z6Gs=
X-Google-Smtp-Source: AGHT+IEugXKaShEuwyWsIgBHzvXUP8Yj0PIRv1MwNC9jdVhGzv82uR2w7bI2RKir9QuKdS8N5UB9og==
X-Received: by 2002:a05:600c:4f55:b0:40d:7d62:80ab with SMTP id m21-20020a05600c4f5500b0040d7d6280abmr178241wmq.117.1705004411150;
        Thu, 11 Jan 2024 12:20:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c88:b0:40e:3618:be03 with SMTP id
 bg8-20020a05600c3c8800b0040e3618be03ls320614wmb.1.-pod-prod-01-eu; Thu, 11
 Jan 2024 12:20:09 -0800 (PST)
X-Received: by 2002:a05:600c:22c9:b0:40e:4695:ddbe with SMTP id 9-20020a05600c22c900b0040e4695ddbemr192381wmg.232.1705004409159;
        Thu, 11 Jan 2024 12:20:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705004409; cv=none;
        d=google.com; s=arc-20160816;
        b=rHutd0PJpzo1hmtZqxxNjpQVgrXtyBFCdoI+nPWRlIlnPmQy9BCxLRihVx+KisRp5K
         6RFrg+7TEnTXluaTHJEnyyysnSOILi92OHhR6mdD4/f+ycf3ftl6h7xI1XGp9LSbqFCd
         htymDa5ZJHRAcah0RLCjb2ysI3CclV9MkpYDmGjr08gCpqsSKrq495f8aKzAp7tdZKdg
         hqK3KHIhgXmeeYKzDDr+WYeGpBGwZp2y7Pw4XKy5m7j8xJqex23veOnQ7AmhYGCXhjEn
         fqXrfKXzpVaepyHNwLFRGEyBau7F4MqDg4VNxeibbynuT95tCe+Jex+XLPWaFYDdgPD3
         Z+cA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=TZR6TAYIYjNrala4xxycmIWnp+59sFxf7ExfprY1dUo=;
        fh=w9eXdKbGWqwMoAi9ZO7gDLjQxF/4EBZnS+jKng4X7hE=;
        b=MdAiZ90Uyma7jZy+NfimEhDsqiq63unPsy0fzKK6FuXLr6RoMIgOqljmyT8v2L27Rl
         pXmz++JwjMjogytA4Onwd/vreMR+rq06ylMsV/o+U/v+aRmhlb9jpIQLP7Hakfdi0QPE
         kvDv4yt3Pmf3xNpiq/HiRPkAvCVOj3BjAilo6Jx0oP6pvS5vkdA5k6USxHz2Nb2n7WZj
         9RQHoRMD33GjfqUz+leHjca0mxl1HCDi0B7DsxywYMTQ1aLUxiJzkmPjfCUhC6MXz76u
         Mo3g1obbCTrPUlHi1UJpbjjYwI9aWXWnzObVD1tV+gaSv2+oKEVy3JWrnkqS3OjUVMgw
         2MPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Pz76U6jP;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id m26-20020a05600c3b1a00b0040d381febbbsi140662wms.1.2024.01.11.12.20.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Jan 2024 12:20:09 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id B49E1B82143;
	Thu, 11 Jan 2024 20:20:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9C575C43390;
	Thu, 11 Jan 2024 20:20:05 +0000 (UTC)
Date: Thu, 11 Jan 2024 13:20:03 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Yonghong Song <yonghong.song@linux.dev>,
	clang-built-linux <llvm@lists.linux.dev>, patches@lists.linux.dev,
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	ppc-dev <linuxppc-dev@lists.ozlabs.org>, kvm@vger.kernel.org,
	linux-riscv <linux-riscv@lists.infradead.org>,
	linux-trace-kernel@vger.kernel.org,
	linux-s390 <linux-s390@vger.kernel.org>,
	Linux Power Management <linux-pm@vger.kernel.org>,
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>,
	linux-efi <linux-efi@vger.kernel.org>,
	amd-gfx list <amd-gfx@lists.freedesktop.org>,
	dri-devel@lists.freedesktop.org, linux-media@vger.kernel.org,
	linux-arch <linux-arch@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-mm <linux-mm@kvack.org>, bridge@lists.linux.dev,
	Network Development <netdev@vger.kernel.org>,
	LSM List <linux-security-module@vger.kernel.org>,
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>,
	Alexei Starovoitov <ast@kernel.org>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Andrii Nakryiko <andrii@kernel.org>,
	Mykola Lysenko <mykolal@fb.com>, bpf <bpf@vger.kernel.org>
Subject: Re: [PATCH 1/3] selftests/bpf: Update LLVM Phabricator links
Message-ID: <20240111202003.GA3418790@dev-arch.thelio-3990X>
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
 <20240109-update-llvm-links-v1-1-eb09b59db071@kernel.org>
 <6a655e9f-9878-4292-9d16-f988c4bdfc73@linux.dev>
 <20240111194001.GA3805856@dev-arch.thelio-3990X>
 <CAADnVQKFv2DKE=Um=+kcEzSWYCp9USQT_VpTawzNY6eRaUdu5g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAADnVQKFv2DKE=Um=+kcEzSWYCp9USQT_VpTawzNY6eRaUdu5g@mail.gmail.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Pz76U6jP;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi Alexei,

On Thu, Jan 11, 2024 at 12:00:50PM -0800, Alexei Starovoitov wrote:
> On Thu, Jan 11, 2024 at 11:40=E2=80=AFAM Nathan Chancellor <nathan@kernel=
.org> wrote:
> >
> > Hi Yonghong,
> >
> > On Wed, Jan 10, 2024 at 08:05:36PM -0800, Yonghong Song wrote:
> > >
> > > On 1/9/24 2:16 PM, Nathan Chancellor wrote:
> > > > reviews.llvm.org was LLVM's Phabricator instances for code review. =
It
> > > > has been abandoned in favor of GitHub pull requests. While the majo=
rity
> > > > of links in the kernel sources still work because of the work Fangr=
ui
> > > > has done turning the dynamic Phabricator instance into a static arc=
hive,
> > > > there are some issues with that work, so preemptively convert all t=
he
> > > > links in the kernel sources to point to the commit on GitHub.
> > > >
> > > > Most of the commits have the corresponding differential review link=
 in
> > > > the commit message itself so there should not be any loss of fideli=
ty in
> > > > the relevant information.
> > > >
> > > > Additionally, fix a typo in the xdpwall.c print ("LLMV" -> "LLVM") =
while
> > > > in the area.
> > > >
> > > > Link: https://discourse.llvm.org/t/update-on-github-pull-requests/7=
1540/172
> > > > Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> > >
> > > Ack with one nit below.
> > >
> > > Acked-by: Yonghong Song <yonghong.song@linux.dev>
> >
> > <snip>
> >
> > > > @@ -304,6 +304,6 @@ from running test_progs will look like:
> > > >   .. code-block:: console
> > > > -  test_xdpwall:FAIL:Does LLVM have https://reviews.llvm.org/D10907=
3? unexpected error: -4007
> > > > +  test_xdpwall:FAIL:Does LLVM have https://github.com/llvm/llvm-pr=
oject/commit/ea72b0319d7b0f0c2fcf41d121afa5d031b319d5? unexpected error: -4=
007
> > > > -__ https://reviews.llvm.org/D109073
> > > > +__ https://github.com/llvm/llvm-project/commit/ea72b0319d7b0f0c2fc=
f41d121afa5d031b319d
> > >
> > > To be consistent with other links, could you add the missing last aln=
um '5' to the above link?
> >
> > Thanks a lot for catching this and providing an ack. Andrew, could you
> > squash this update into selftests-bpf-update-llvm-phabricator-links.pat=
ch?
>=20
> Please send a new patch.
> We'd like to take all bpf patches through the bpf tree to avoid conflicts=
.

Very well, I've sent a standalone v2 on top of bpf-next:

https://lore.kernel.org/20240111-bpf-update-llvm-phabricator-links-v2-1-9a7=
ae976bd64@kernel.org/

Andrew, just drop selftests-bpf-update-llvm-phabricator-links.patch
altogether in that case, the other two patches are fine to go via -mm I
think.

Cheers,
Nathan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240111202003.GA3418790%40dev-arch.thelio-3990X.
