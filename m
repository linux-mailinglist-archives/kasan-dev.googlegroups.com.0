Return-Path: <kasan-dev+bncBAABBM72QOHAMGQELK4UREY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 931EA47B58E
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:01:23 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id q13-20020a19f20d000000b0041fcb65b6c7sf5211176lfh.8
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:01:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037683; cv=pass;
        d=google.com; s=arc-20160816;
        b=a/fLtG0a4KKe8j+RK55ylZiKTs4aQgQwP19xFY3Ja2UfnHri2vIp1XdM0nxaHRNHze
         7svaZSa7RsQvJWcMVj4Eiy6LF2Hv8FhavxGrufXAdobekyPyPvHMHZnfeZx79KSYRC/W
         2aB8F0dhQ/mw/zhR+mKNHXUEPG+FbLLxDQNYJfaKdMiGsRLfg1e88zc0iE/0QucKkvsv
         Kc/xHeGjBvYUAGIwc4G5QN3Rr30TJZJJf4fCXlni47CooM60gJpR0BPWeopNJRuAWErw
         OyidzlcMPn18epoTsExZgAfQ9YMLGh0wPcgtjbkV74Flnhd47TWQ/BerCG+WmoUnanqv
         /yrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3e/b5aV7SIPWHhBjSt7kmfeTfvU5qvWhQlZARj+0dnY=;
        b=xkmrVQuuXXhZ3AXhf3VxKQ03J1yTv5Q9BPudZvPMe59n5TukTYy0TEIaF4yEArfE40
         Y9lIiF0QQL5PTBHOV0SO9sFnLJ3R83Zxj3gP8zcZ3d/shZ7QgQ2+lb/MBPfe6tQRpbVc
         ca+GclvjtkH3nYrEUv2SmQWSO56G9gbhfrsUUt/twoD+Ezzu1CPxX7UjANg0XxCyZ74D
         K7ilF4aP67J0ZBHTHy+T1H1v+Bw1eHkpFxnj0fpwVYMEjhvtN/0B88NMZu1/9Q+zU9vX
         /3FSY+fBuxCJiL1IiKOjVKcNzg/IBremTsZ6IR9Jdx8wzgxtNppqah1eQdK2mZpQqY9A
         pSHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=psD3KeET;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3e/b5aV7SIPWHhBjSt7kmfeTfvU5qvWhQlZARj+0dnY=;
        b=NBSPjDDQkIKyFSXXTkXrEDJs0kbB4c36MzdqnOEApIwXOaKp6nUi8JSFN7+PbTGFcQ
         QdHRLVgaae/fBHI74N+KMhqKqRHQKfss4zuLXDQmyK+Auq0CpVy+cnUueUP/wf889xom
         73nUXjRceS+09jiMsSme3rGt97aQq5DaLVfWow+wUK00NlsSiS1JGJ44ziwrhHJra6gN
         1IghVkUb4vpTTC7KtPrsb29ztdU8z9gwqffjECEuxK+ypn+QZV7rUKsgtrK9FvCGDS8A
         /p/5zcq+tYX8Gxn0k6zaGWcik6qx7XJFZtaP4DiL1VUzHvAS4lfDLVO8WPC1zIjv1YrL
         S0aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3e/b5aV7SIPWHhBjSt7kmfeTfvU5qvWhQlZARj+0dnY=;
        b=i/6txClN2Y1sIAteS/lGOx6gytyDts6MqEboQ1T4HpPalvCvrFqIg8bUTgEvWEnweD
         56Or9sIZPh08bt5nSDQ12jgKewHri63L/+UqpcAqVnMW6Hc6DXBejjuGnNgotzZ5o1I7
         CQvHi0vJEIKlK75+hT60tJjnF9jsNyzEp3Me/hLDp+PAAKGgZY2k9fHqKT7izJpZFt1t
         a9cP/y83FEkjx0vw/D74Dz488qVMJSUtgBsjDfETM1DLGtDHiGLsOCbGuAgjU5atPs4r
         yPsKddOmlkOwxRsbI1tzeZnacXMPyI5A/T9ZB/WbH7Wc+RLUrlsVc41DNtzoRyVZISNm
         CSeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dmXe60sOeYBZ1whDAZ0M8ek2BuUpzN29Ve9D/p2pFQoYnccK6
	iyXSgbR+LWeiV4xOE36cfAM=
X-Google-Smtp-Source: ABdhPJwawPDyupxCXci7bbONODdm6fLty8kuZf51ARAyFH60zzjV0fWxL2TLchkMkuhBRZGGsrq34Q==
X-Received: by 2002:a05:6512:6d2:: with SMTP id u18mr128998lff.375.1640037683213;
        Mon, 20 Dec 2021 14:01:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls801487lfu.0.gmail; Mon, 20
 Dec 2021 14:01:22 -0800 (PST)
X-Received: by 2002:a05:6512:2520:: with SMTP id be32mr155659lfb.634.1640037682543;
        Mon, 20 Dec 2021 14:01:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037682; cv=none;
        d=google.com; s=arc-20160816;
        b=k+myR3IURbxKbPX4pGbVKjHIMtDfTbVf2gqI6NhcozY08whhOP9zsYWgrQHNlUj+Gs
         XpQGsgptC0gs8FoBxpa4zOzTLs3vEtnIiRcOuquPSjSJ8LQfzgby1UbNhGtwnZeHEQ64
         aZ/HY0uSFApLfP2fymGO4oJooIxQVez+nq1/irCOdpsv1ZHeO9yX10Tkg8jqRQ2bmoS3
         6uLWTXHK+CNFjkga8dkjGtWj5cKEUjbY2G3gkD2eQNhJ8LhT/LWPKHV5OdS8IPtaIdmb
         cgNJzLAleEaJMdSqdezCIMRVhqP/5J/DYqFnUL2GZQroCCTYUyhaZL8h31SXFqLmB+f7
         ohlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=T+YMJBAzt/nU23GNh+s+gTj6PS6iuM5TpfUBadGWu7U=;
        b=FPXnaH5+Fovg4mfEPPq99uYNSzrPrVHLdpzP7SJvhHQ1upoXVk8ttyJ/qWwH+c/HQk
         Wfa3u4X7Cov7sYhkISR4CAY9bJ+52RTzFM+z+Dp3ZNfCHMYQ++llY5piG5InsrsY30Q2
         us8fwV9rCBrxWFw3e2ETZotidTVGBw7qTtSBQEdPTQsCUTtY6cWimAue11BN3GxhwN7b
         2cRj6jjcu5S6ubzVqq2LSI+LGFD1sHj5XaNawVrwPIC12ukdQNTapOPkSqHyNqHCHRZu
         1i0J8JuNF318T4yr1dhEsPJjBugxG+UsIz5/UJvl6CTSJyQVXCxQkeK1xBBlD7GC6yRk
         mEfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=psD3KeET;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id d18si883053lfg.3.2021.12.20.14.01.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:01:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v4 22/39] kasan, fork: reset pointer tags of vmapped stacks
Date: Mon, 20 Dec 2021 23:01:01 +0100
Message-Id: <c3fa42da7337bc46a4b7a1e772e87bed5ff89850.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=psD3KeET;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Once tag-based KASAN modes start tagging vmalloc() allocations,
kernel stacks start getting tagged if CONFIG_VMAP_STACK is enabled.

Reset the tag of kernel stack pointers after allocation in
alloc_thread_stack_node().

For SW_TAGS KASAN, when CONFIG_KASAN_STACK is enabled, the
instrumentation can't handle the SP register being tagged.

For HW_TAGS KASAN, there's no instrumentation-related issues. However,
the impact of having a tagged SP register needs to be properly evaluated,
so keep it non-tagged for now.

Note, that the memory for the stack allocation still gets tagged to
catch vmalloc-into-stack out-of-bounds accesses.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 kernel/fork.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/fork.c b/kernel/fork.c
index 403b9dbbfb62..4125373dba4e 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -254,6 +254,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 	 * so cache the vm_struct.
 	 */
 	if (stack) {
+		stack = kasan_reset_tag(stack);
 		tsk->stack_vm_area = find_vm_area(stack);
 		tsk->stack = stack;
 	}
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c3fa42da7337bc46a4b7a1e772e87bed5ff89850.1640036051.git.andreyknvl%40google.com.
