Return-Path: <kasan-dev+bncBCT4XGV33UIBBH723KTAMGQE2B65IHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 278BB779AE4
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Aug 2023 00:58:41 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-40ff56e1c97sf69771cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Aug 2023 15:58:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691794720; cv=pass;
        d=google.com; s=arc-20160816;
        b=TPElDy1lqEtEEIo1zUrvpt5HgapbYG8UEb9V5TX8CRXVgy5xwau9AHKyxJ3M/5Rno6
         EvVjzAsyCXOX7QVN43SjNEIS7VJlWsq3Di7+YPnRSNeksGZNRGEgcs7+fGAtqRf3xiqJ
         YOVcxVzOX/UvtzbIbZkZmjzXSVg45zc2YwK2l/1mNt9YcIHOCRZnGOr9fbf53qyV/ksg
         jC8P+8BpfW7SnJHDaZtNxjL3jRym+bE7J7J34nGYS0Y3Z6zKoILGM2rGE82E4jdYsBc1
         ecPkIIMbBU3Uu6G4BspnFmiLWm9/8CbKJAdwacfVNJdApFgNsvHVB9J1wFnYPvzqcKqK
         YrNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :message-id:subject:from:to:date:mime-version:sender:dkim-signature;
        bh=lydd3WfOEwmZ1nLhAyweHcpEUWDJ25njfRDqYYkEI4s=;
        fh=0jO1JOzt27HyKkrjcL5NMcwM8KGfmM7wNTpPS5AH8Ow=;
        b=wrOL6JttcD5NVhuD8Dq6RLuZW/33yA2wF02gsBwtrOwv8J8o494sWUgIPJWjytAKqe
         7IlKCEgOi2zESgBGHqXUqI6q/kSm4XQASGR8lVtfMr99t0W+dJzbvGRtNIqi0W5KKJEG
         y72iFpXQPyMrkZk0bV1i0+rtr0mQ0d7457QCDUqL4GX/alO0rSRpBDzHwcGdUnuddy1f
         E+Xu/qYQ8S033PlfE3jcajyySD8LbCslNWlocTSZLCQY5+Ma9A+DvRoN9Ook59FFRr7i
         Tgq3k659laR29d5tFO/bGX45gFW+vKBB5qC/+cK1L6uQeYkcYqxMsZFffMFtOvVSHOu+
         W0hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LvgDGola;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691794720; x=1692399520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lydd3WfOEwmZ1nLhAyweHcpEUWDJ25njfRDqYYkEI4s=;
        b=JOmXxmAYXY4k72AXZQNQNKHPP8ithUTIuW1HhSRYLJvSfPt9BkX01fu/H1UFyrfnHj
         SSNMlum5Wyoyssx3tTh0ygf6xPJJ+h7lLXxa5xy8dC5AVZZJ7NTKQN+nEhA7G4KAgtg/
         +OckRxAzoq0vqc0vVYrUEVZrLLvxCrsE3dWvjXUNY642izMtDmCFBNzY8MiIWAHS3iNN
         sgZ+DE+R+CaA5K94l3RfiBg0X/vkztzlL9PWFsFL1d9ZkcBTQWc5OAmiRxnhNp3mb4w6
         hCWIcVi4RES5723Q5RP9y10j6tdOJmD6CC6WkYRI9jT+vcDqa4rqiu3Bz1izWUdAtCkT
         RDiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691794720; x=1692399520;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :content-transfer-encoding:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lydd3WfOEwmZ1nLhAyweHcpEUWDJ25njfRDqYYkEI4s=;
        b=f/yGaqWDStE/QsB15akTTk2dzPI/+DA4t1KzCKRcnOht2WhMPuTaRAhHx67bjXT0Wg
         NOcu1Evp6/hLWfwL5ac+TbF6HbjbbZxS9jWiFceHbfnCMKaob0hwNyrCyN7ahHNG459U
         EJlGr+6HI9h8SHWtfLH3y4y8yJqx4BSqwwjYJDHmRm/jXspqd+E3nnr8hQidixtEHfWG
         anwvy32QIYH/eVFfIY7jAWHZOEdj4UUzj2UL/i9KcRZFd7/qOMurkiu6elXT3wCiJqqd
         w2yIhaQ0sbJ/M2RVXZybTbuoZ7G90O5c4Upl12LOsox3il/fT0ZJmOwooVsGoo6zfOMk
         S5Fg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw9kPavutm+ZDGa+exjmHzzZU0Mfov4aZf1alc6ZfJ2OJSJ7I7Y
	ef9y40zZ66dDbef3IAFcDNA=
X-Google-Smtp-Source: AGHT+IHr7qTaKKH3eTeCSJKDxIPUzm7pouh9pGH7DPuua4e7Rq3jrenMx1OhRUSbXgVmwmxkcOGwvw==
X-Received: by 2002:ac8:5841:0:b0:3f8:e0a:3e66 with SMTP id h1-20020ac85841000000b003f80e0a3e66mr304668qth.3.1691794720062;
        Fri, 11 Aug 2023 15:58:40 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f04e:0:b0:63d:253f:eb99 with SMTP id b14-20020a0cf04e000000b0063d253feb99ls2658971qvl.2.-pod-prod-01-us;
 Fri, 11 Aug 2023 15:58:39 -0700 (PDT)
X-Received: by 2002:a0c:e150:0:b0:625:bb19:278c with SMTP id c16-20020a0ce150000000b00625bb19278cmr3032554qvl.2.1691794719203;
        Fri, 11 Aug 2023 15:58:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691794719; cv=none;
        d=google.com; s=arc-20160816;
        b=GjTobYv1GDyC9p+C+vwGMz1aBTV0fwNDTMNCd6tGTV5HWm8CD2FE93o8JaookTJkKG
         ufbZjGnvZk2Q0Jg0Y7Iy3bhCWtsXPz+iGo7xgXP+GD33C27YCYPogqZrVsKn8jmawrZt
         pjH9a29cXLkXWy5AQdHT8IyLq3zXctKEzf6VmCp+uTzMAQVSVClJx2VCgQvFGihc0ZzX
         XyvU5dvCDBxit2m0G7xdpuL94K8IwJR74qK3XtHJKZfl7yjDTMzOace3J3gwkjezG0EV
         0z/DRaHAvuDPIKe0Gl59ubFjuMDgOnS46erhhBizNk15KzVL8wPBIcJFeEH7c0yS772K
         elYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=abB26IkPeSLFx1uSjnrK9yFeLYS5H0Kiif+mS/cM3xw=;
        fh=0jO1JOzt27HyKkrjcL5NMcwM8KGfmM7wNTpPS5AH8Ow=;
        b=pCUkIX4ktZ1m7tDfpNG/ZWEsxj9y7HFhZQKmfNRYBFz6WlswLKHHlu7GGMW6BXN+tN
         KERpge+7e9sJ8aHn0l8veeDF4qBJ6nuDYkTB8hOJ+1BlJbtRzHgjcKVgUR91T8KuKTuL
         upKpE4CsLWOZjc8ydbjUyXdrVfpUxTSkWs2OXv0Nj04gxXuTUZxgO0kkLUvxBYwoYGvg
         +rQMbCKQuq+dg08M4YNoR6I7lOpLX/pmJvwDVWunnA0/E7BNE580/Qp4DBfJ1BILGkNO
         F0LERimF7/UDFmZN4IBrqeemNe9nRcZrsz72UL3r7ND3c0JV9IPqJBD20zrfnKpAiAZq
         eVhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LvgDGola;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id pc6-20020a056214488600b006261d48d4c2si310713qvb.0.2023.08.11.15.58.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Aug 2023 15:58:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9C2556699C;
	Fri, 11 Aug 2023 22:58:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F125BC433C9;
	Fri, 11 Aug 2023 22:58:37 +0000 (UTC)
Date: Fri, 11 Aug 2023 15:58:37 -0700
To: mm-commits@vger.kernel.org,ying.huang@intel.com,will@kernel.org,vincenzo.frascino@arm.com,surenb@google.com,steven.price@arm.com,qun-wei.lin@mediatek.com,Kuan-Ying.Lee@mediatek.com,kasan-dev@googlegroups.com,gregkh@linuxfoundation.org,eugenis@google.com,david@redhat.com,chinwen.chang@mediatek.com,catalin.marinas@arm.com,alexandru.elisei@arm.com,pcc@google.com,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] mm-call-arch_swap_restore-from-unuse_pte.patch removed from -mm tree
Message-Id: <20230811225837.F125BC433C9@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=LvgDGola;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Content-Type: text/plain; charset="UTF-8"
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


The quilt patch titled
     Subject: mm: call arch_swap_restore() from unuse_pte()
has been removed from the -mm tree.  Its filename was
     mm-call-arch_swap_restore-from-unuse_pte.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Peter Collingbourne <pcc@google.com>
Subject: mm: call arch_swap_restore() from unuse_pte()
Date: Mon, 22 May 2023 17:43:09 -0700

We would like to move away from requiring architectures to restore
metadata from swap in the set_pte_at() implementation, as this is not only
error-prone but adds complexity to the arch-specific code.  This requires
us to call arch_swap_restore() before calling swap_free() whenever pages
are restored from swap.  We are currently doing so everywhere except in
unuse_pte(); do so there as well.

Link: https://lkml.kernel.org/r/20230523004312.1807357-3-pcc@google.com
Link: https://linux-review.googlesource.com/id/I68276653e612d64cde271ce1b5a=
99ae05d6bbc4f
Signed-off-by: Peter Collingbourne <pcc@google.com>
Suggested-by: David Hildenbrand <david@redhat.com>
Acked-by: David Hildenbrand <david@redhat.com>
Acked-by: "Huang, Ying" <ying.huang@intel.com>
Reviewed-by: Steven Price <steven.price@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Cc: Alexandru Elisei <alexandru.elisei@arm.com>
Cc: Chinwen Chang <chinwen.chang@mediatek.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Cc: "Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)" <Kuan-Ying.Lee@mediatek.c=
om>
Cc: Qun-Wei Lin <qun-wei.lin@mediatek.com>
Cc: Suren Baghdasaryan <surenb@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 mm/swapfile.c |    7 +++++++
 1 file changed, 7 insertions(+)

--- a/mm/swapfile.c~mm-call-arch_swap_restore-from-unuse_pte
+++ a/mm/swapfile.c
@@ -1778,6 +1778,13 @@ static int unuse_pte(struct vm_area_stru
 		goto setpte;
 	}
=20
+	/*
+	 * Some architectures may have to restore extra metadata to the page
+	 * when reading from swap. This metadata may be indexed by swap entry
+	 * so this must be called before swap_free().
+	 */
+	arch_swap_restore(entry, page_folio(page));
+
 	/* See do_swap_page() */
 	BUG_ON(!PageAnon(page) && PageMappedToDisk(page));
 	BUG_ON(PageAnon(page) && PageAnonExclusive(page));
_

Patches currently in -mm which might be from pcc@google.com are


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230811225837.F125BC433C9%40smtp.kernel.org.
