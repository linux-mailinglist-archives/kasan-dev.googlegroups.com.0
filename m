Return-Path: <kasan-dev+bncBAABBH7TVHZQKGQEZ6IXPLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C00118382B
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Mar 2020 19:04:17 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id d2sf4499404ilf.19
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Mar 2020 11:04:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584036256; cv=pass;
        d=google.com; s=arc-20160816;
        b=H0aRyqv1bxblIcfZVefnPmY10aNMsDqVc9C/pyp4qbqKBMbuTBJa6Tlyo+Kavu+sHf
         8YGTCF58ZhAkKbtaT3Clw+J5yVYHtkUgdsAHSUj8s3T91oyodwEPU8iPxNu4tPfLog6B
         NrfMgKdWuAXIUEQa/dMUQHNMqF0oCcQUre6s8GBN5Nrebr4Avm9+x9IIeC33YjNz0C3N
         y80LwWhW2mRNJ8VjRKjAgdPdokSkd93ovUQBQXk/yhnffGFEkfbxIeykhCVm9NSuuPFC
         xdf7QvUVmysGkjhwsGbffjtybb4IYZDUCg4RYPbsS3hypD2b4HggtowW1Wkb/SVKCzzu
         w7RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=eBllZXpvMTGJ6mhG4VH6xxZSgfuwvYlziUtvWKDthLc=;
        b=fpXvIm+a5mOfcE5nnkoBmQoXV14w3bdx8Gdd/evM/QNiegVvXc39Vw9wpnbPj3L9Yd
         +g+19EKofTrlfbf9aEHHtJDlHCt5DUKG8OJraZ5GAfjzji08JVAGT0C3NKJfWnN/kE2R
         mN/NbbnFsHPu2OStONwLAliOeH9sG3wV7OeeHpTFgvNHcOrZswJ9m9FV+/V+Udwx6e4g
         FMJ/DDRRjI6mwN7tEF414IPf+3m5oI6kSqOMLellVklztCTpMAzF9hP/iAdOLQmwTYk0
         PHWw7lgO7/1DvoJms4KvaZTtss0NfHeh8ZGisTjn5XMhCuU3oZdMTy1YA+dKTYAwYd2M
         lCsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=YCrpA8y6;
       spf=pass (google.com: domain of srs0=kkof=45=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=kkof=45=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eBllZXpvMTGJ6mhG4VH6xxZSgfuwvYlziUtvWKDthLc=;
        b=YhlkIGtSCmsCQqnUUMS+F040CSwrBHQZ20I78rksLCLZzLogbeymHJftR19WevG93G
         Qj2qRs4NZhyDYEfxVATixOyoJAvWKQ3aBumj2rYGcGlqCLrZ8LtVvDbXOgLmbtn1/1nc
         zrtclIQplXu620tfcfvrcMWyNgYEevzf+XvGOZlu/wvceq9XvK7+UDPOuz8nYaQfIlLj
         CU+b4MyErjpPFEU9E6/MeFqjrM2FhSd21HbDvHNMfdmK7kbavMDb9vKqx2ogX/0ayTn3
         WYJGy32xSkcOAXRcBGdb2x2yQshdJmrqCXjoCBkJU62sJegCDO/m29fKuqQejcuqCKzq
         iOOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :content-transfer-encoding:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eBllZXpvMTGJ6mhG4VH6xxZSgfuwvYlziUtvWKDthLc=;
        b=fj53PVsdnWamks59dDsqrB1RpvkApi5vvxgQDwK7jQ/RqzgwgZpeTFQeeXuBwM/Xbd
         j+9gDRug0bxCLM2bbMTGsTCVSDNhRkb20Fq83HdZs3iYWu50q8yBdeQ/nXyrfSRf/7U2
         PiIzYqIGzO55UW8k9Kn8SeVgBSyh049klYjeyFqH6wbwIf8f5ys/JpV3ePSOCkH8bcBI
         WP+fRv0kKwUeoKfuUJ9Z5yzq+QgjZP0y4alIaC/HMletPY9eCTBh/R+7TZ2K8wjA6jmW
         kbmp2k6XHxF5fWyk+ceBzvETxVKckpEMQECz1YerGi4WKDDYPK3LN1fu3zTpk5sBJ4vB
         WCEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3TjGIsgSs1TH0FUNBrMHGB+EnoAUE99Cbm1gYqf/GcDuWUbh0O
	8AA/3WkKj0DTVta64zR1TPY=
X-Google-Smtp-Source: ADFU+vune3rfCqnSGtj9BAcj39b8ncB+j40vqrKVWC59NBf/0/y8R6KKZrabvMEHWXueV1slYXPt4w==
X-Received: by 2002:a92:c80e:: with SMTP id v14mr9969441iln.259.1584036255892;
        Thu, 12 Mar 2020 11:04:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9cc6:: with SMTP id x67ls1942904ill.1.gmail; Thu, 12 Mar
 2020 11:04:15 -0700 (PDT)
X-Received: by 2002:a92:8901:: with SMTP id n1mr10112306ild.176.1584036255588;
        Thu, 12 Mar 2020 11:04:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584036255; cv=none;
        d=google.com; s=arc-20160816;
        b=tMabIh3wqsEVxn0CvTHslIGfGJESSNbShixZItvCR21KY+CABPw+YZTfJYvs7IsqgP
         v/a1AzJd34xqwsptwKqlF/W3Iem/XTEmzk+TyEcvnieRPViXww6roOtCRNeu953pe7Z9
         6q8MLEo3OY9nNz31JrWK4afEjEGlfCXeBpNp+xfbU//kZi/rYwN21mpfWS0KEzPEY/oM
         LLWpE5ZFUUE6fDByK3HSiyZh9Cf3uRMcgxdkaj1f5/O9iDatSjcLbrLRE1XZsqdfnQ8A
         OBkTCWm+K69zykSqrvX3H8BTDedyfteolA9idNYcjQLSlfTQk/9mCReTgVyE4JHQmPsx
         gB0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=aoPxyaLc2W9D+Zw6CyXbC37/r/1TOmMMFKbT/8ZAYpM=;
        b=w5+QgyUIMDKybbgWqGLzAkFKYk2mEUImcQ/h1j1oioh7aPu9ywq5oNqja8UaN7Loks
         rUjifjsiBiQx2lqVed2OdxZIS0wEX96B0GpXmd/EanibVGmiVLJHd8TQ1FOLx+Vi7Sv3
         D+y/kyzi23KM9eN4gEoNZRItpBgU5GXexC+pXInYpSKcjn6MiMyFQgUSodYsM/sdM+kK
         y53rvlaaRTmxl0rED65zkjA9KGcbacf40cqbiKJY1P3dPZ4+j9xrv5HIiW5QZ55eITjE
         Lv6e2ueMgfezFoWWPu5Iw6dykV0sYVdTt6opmfhtAlLj7TBI6RqZGgm+kxEM34P0bn3R
         J3/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=YCrpA8y6;
       spf=pass (google.com: domain of srs0=kkof=45=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=kkof=45=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k88si322280ilg.1.2020.03.12.11.04.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Mar 2020 11:04:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=kkof=45=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C54BB20663;
	Thu, 12 Mar 2020 18:04:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id A0F9435226D0; Thu, 12 Mar 2020 11:04:14 -0700 (PDT)
Date: Thu, 12 Mar 2020 11:04:14 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: Re: [PATCH kcsan 27/32] kcsan: Add option to allow watcher
 interruptions
Message-ID: <20200312180414.GA8024@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
 <20200309190420.6100-27-paulmck@kernel.org>
 <20200312180328.GA4772@paulmck-ThinkPad-P72>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200312180328.GA4772@paulmck-ThinkPad-P72>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=YCrpA8y6;       spf=pass
 (google.com: domain of srs0=kkof=45=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=kkof=45=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Transfer-Encoding: quoted-printable
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

On Thu, Mar 12, 2020 at 11:03:28AM -0700, Paul E. McKenney wrote:
> On Mon, Mar 09, 2020 at 12:04:15PM -0700, paulmck@kernel.org wrote:
> > From: Marco Elver <elver@google.com>
> >=20
> > Add option to allow interrupts while a watchpoint is set up. This can b=
e
> > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > parameter 'kcsan.interrupt_watcher=3D1'.
> >=20
> > Note that, currently not all safe per-CPU access primitives and pattern=
s
> > are accounted for, which could result in false positives. For example,
> > asm-generic/percpu.h uses plain operations, which by default are
> > instrumented. On interrupts and subsequent accesses to the same
> > variable, KCSAN would currently report a data race with this option.
> >=20
> > Therefore, this option should currently remain disabled by default, but
> > may be enabled for specific test scenarios.
> >=20
> > To avoid new warnings, changes all uses of smp_processor_id() to use th=
e
> > raw version (as already done in kcsan_found_watchpoint()). The exact SM=
P
> > processor id is for informational purposes in the report, and
> > correctness is not affected.
> >=20
> > Signed-off-by: Marco Elver <elver@google.com>
> > Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
>=20
> And I get silent hangs that bisect to this patch when running the
> following rcutorture command, run in the kernel source tree on a
> 12-hardware-thread laptop:
>=20
> bash tools/testing/selftests/rcutorture/bin/kvm.sh --cpus 12 --duration 1=
0 --kconfig "CONFIG_DEBUG_INFO=3Dy CONFIG_KCSAN=3Dy CONFIG_KCSAN_ASSUME_PLA=
IN_WRITES_ATOMIC=3Dn CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn CONFIG_KCSAN=
_REPORT_ONCE_IN_MS=3D100000 CONFIG_KCSAN_VERBOSE=3Dy CONFIG_KCSAN_INTERRUPT=
_WATCHER=3Dy" --configs TREE03
>=20
> It works fine on some (but not all) of the other rcutorture test
> scenarios.  It fails on TREE01, TREE02, TREE03, TREE09.  The common threa=
d
> is that these are the TREE scenarios are all PREEMPT=3Dy.  So are RUDE01,
> SRCU-P, TASKS01, and TASKS03, but these scenarios are not hammering
> on Tree RCU, and thus have far less interrupt activity and the like.
> Given that it is an interrupt-related feature being added by this commit,
> this seems like expected (mis)behavior.
>=20
> Can you reproduce this?  If not, are there any diagnostics I can add to
> my testing?  Or a diagnostic patch I could apply?

I should hasten to add that this feature was quite helpful in recent work!

							Thanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200312180414.GA8024%40paulmck-ThinkPad-P72.
