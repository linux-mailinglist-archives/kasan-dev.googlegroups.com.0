Return-Path: <kasan-dev+bncBAABBQGORGIAMGQEVRNLKRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A01D4AD874
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 13:51:14 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id y13-20020a170902d64d00b0014cea2afd46sf7375192plh.12
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 04:51:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644324673; cv=pass;
        d=google.com; s=arc-20160816;
        b=FJ5IvWGS9/qvUQMcWPzxkvqp36CXospFb37IXxGqhhazeZcrWZJ3ZTZjF9LWho+trB
         H8g63TZYnDXfWxBVUONfK4Vrh/DRxXcuNwHzjfTaYIs6Hu199f4Y1ZoKAQAa28k8dWUF
         nboReDn+jAQuyoj0CXVrfiUxCD1ceQ67xAIU4i3FCliyCwkvzaglUJuXzjotNlpOF3My
         1//P2O1y+ab4FtehXfWzKDxOtUK9djDy7YUPP7kTyY0Iv7jqXx3nlA8sGn8f0O9lLjqD
         z7WKVmmUFdmZ36MWAozIfbxH9Rqlw4uxIJc0C2C4HFvj+T9ZdXqNHRMqwjEwFlFvnkkx
         3vqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=wxzh+YiK/6oBbiHnTT0AxbV+QjrZpKftiHGMEFeGAdU=;
        b=Lr5JqQPeneYiz+FX0QVKfWFpywM3z+3R7zKmbTepENGDXxSdGGwUbSWuMDcqJ7sg9j
         IaJZuWUkbDoufXk9XVa2MCSZl95P3PL7Rn2XADYBPbVY+RhKSIxgJdrMY+CpBRrLEwgx
         DlXhkRG1VZ5swcgO8Um0qg2aofOcwF6xdqCrYTR43XM742IM3Zf06w/khxw7JJYeo2/v
         1ageyl4mpuVvOASy4IQ4zy3QhbTh7SlOZ2G4sOwAOG9NRBOb3oeFR8mDW7/bjDmWo1MB
         xLcvAkTfZ8SaaT325+wtBPsCQQabsSUOJIknU548EdqXGumvy3nG5ZqFG5YJ2F41w0M3
         Wt0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wxzh+YiK/6oBbiHnTT0AxbV+QjrZpKftiHGMEFeGAdU=;
        b=OM6nZ1K4aSeFON046FvzbHn00E0ZwRrVN4dPz0u1bVK/A/xDrgBJu+LSed5YaxAF8t
         831Sx+ZpbfEd4UOFaqh7kof2ajEdUvgbVq4smmky0Rc2cVerrzktXSviPqN48YO/Ebg9
         6dpMGdcftIMFyyU9iTE6SP0vZCeCh8p+MojoPTrmrGzrDYfN2j7I7lvXOJisYIsdR6vY
         YI/xtb44/fKPY68bQD8gHbGDoVUDA6vBvVGQJit0UiKRgxzvz2mHfgPi1szrH9JWZ0UG
         MFQWJrKV/mlUd7O7xBTFUPwfXCYuIoXymf+sGQVE/p55FPnOMajCI/Dk0YHWrxvoLJ0o
         +sZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wxzh+YiK/6oBbiHnTT0AxbV+QjrZpKftiHGMEFeGAdU=;
        b=M8ITWfByepRL+cHWe5Xvhnl+z/QWsWvEPo8hG5U5hXTRhnfT8BL0ffWxjqsrOwEu2y
         dG5+8+EaN7ykqFF8VB3jtBo9yP62ZdWJ3/JDCNm187Bpx2Le36WwchlmQUlLBgcfYqcf
         Gnk3WVyrsia6i96LPso03PTXwW1DrAhJQCiFZ7VgvXyIeHBrxK2ZJJfG6+B54OFtBO4J
         eOw4nAm2M5bsvkCnwFctaqtTfZ/hOkXW0ofwk81Tjb6hugOB4PQOeKzml24BhrgkbDF3
         PJuutDBe0JxlnxaWxeYPllKyhzVPHaipJdcy8ZEvejHgUtRvqKvxjO2GKyaNiuyQwJ42
         uWBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oMNhmLbLKqoDniXltYfMoXqSyje26wsR7Vl1k7IIEZMdICaeC
	9IKo9xu21P8noY2CbnHBfPw=
X-Google-Smtp-Source: ABdhPJwv8PBzSZQsML2cmsVqfec+9XOF2/FmsJbqrC5PAiTLJq311fitiYjuHtauXXGkA/8z+VAT+g==
X-Received: by 2002:a17:902:b708:: with SMTP id d8mr4170894pls.86.1644324672943;
        Tue, 08 Feb 2022 04:51:12 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:38cc:: with SMTP id nn12ls2000094pjb.1.canary-gmail;
 Tue, 08 Feb 2022 04:51:12 -0800 (PST)
X-Received: by 2002:a17:90a:be0a:: with SMTP id a10mr1211856pjs.0.1644324672347;
        Tue, 08 Feb 2022 04:51:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644324672; cv=none;
        d=google.com; s=arc-20160816;
        b=N9zI0T6Y50k7Y1Sap2JwDE+VVKdXV0gHOyeFeekb/N2myunhw+0ob5/wfP/4mxsr8c
         AyevAlLZ335SDLaACvrfiU5K8OPo6C1Mi5z6qZrj/xwzgR2VuabvV8tHn7QWyahgUXvF
         dD6Pl4GOQkkhwIacoVCX9cXE/stdzANOeqnFMb+8Wzxmoh3ijiqlnmgm8f/wsBa52C6a
         nC0xz5rN6cJK3H0KSevahWVzxIgfnGPM5TxtwIEdJaubf+m0OybM78D5y/PN1chrAqU1
         FrKY2A56LFCYRGfltdCiA7/UWr03J4omHbfE3lyEHXL/AfMMa96Gfkwq6euMJhdpqqQi
         bBYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=WYmBuiZ3Ug7ublOeUp9uLH7GqaFhglkXXFfk+H20NJ0=;
        b=EKGBG1tUgsTcKpafWayHImwuDbrXMroBuplWn6417go1/854Xsc3mFCyLkLuFi5OJg
         kHdY+rS2zLoOrKx1jm8GM/1hPCE+RKbvqJ9lTR69KU0fSpYFt9PT2SJCMwJBOJKB7x0a
         FbMPaD2AhwVt/59ERCMvOns0oxy5NbkdA1SUgv22isrKRx9z0xq5ChT5HSUD9KuqcTMY
         ZjDa4QYGJ7gWCth1juoQfvyiY67d2YDs13JWv6GuaW0zCFVbmfX9l9es7Pwu4usyYK4x
         Y155EqTo1+3FbajBJfIC/dqA6VobcFop/b6SiCM3vy9RgcTPG3Ks6/Oo//yTah3usSBZ
         75eA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id k17si361161plk.10.2022.02.08.04.51.11
        for <kasan-dev@googlegroups.com>;
        Tue, 08 Feb 2022 04:51:12 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9DxL+M6ZwJik0oIAA--.26524S7;
	Tue, 08 Feb 2022 20:51:09 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Xuefeng Li <lixuefeng@loongson.cn>,
	kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 5/5] kasan: no need to unset panic_on_warn in end_report()
Date: Tue,  8 Feb 2022 20:51:06 +0800
Message-Id: <1644324666-15947-6-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
References: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9DxL+M6ZwJik0oIAA--.26524S7
X-Coremail-Antispam: 1UD129KBjvJXoWrZF18urWkGr43CrW5uF1Dtrb_yoW8JrWxp3
	ZrG3s2kr4xtryUXFs7Jw4UJr1jyrn8Ja4UGFy8Jr4rX3y5XF15GrWIgFy0qF45W3yxZF1Y
	yw18try7WF1kJaUanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUmj14x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_JF0E3s1l82xGYI
	kIc2x26xkF7I0E14v26ryj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2
	z4x0Y4vE2Ix0cI8IcVAFwI0_Ar0_tr1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Gr1j6F
	4UJwA2z4x0Y4vEx4A2jsIE14v26rxl6s0DM28EF7xvwVC2z280aVCY1x0267AKxVW0oVCq
	3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7
	IYx2IY67AKxVWUGVWUXwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4U
	M4x0Y48IcxkI7VAKI48JM4x0x7Aq67IIx4CEVc8vx2IErcIFxwACI402YVCY1x02628vn2
	kIc2xKxwCY02Avz4vE14v_Xr1l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_
	Gr1lx2IqxVAqx4xG67AKxVWUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17
	CE14v26r1q6r43MIIYrxkI7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_JFI_Gr1lIxAIcVC0
	I7IYx2IY6xkF7I0E14v26F4j6r4UJwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcV
	C2z280aVAFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2Kfnx
	nUUI43ZEXa7VUjAnY7UUUUU==
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

panic_on_warn is unset inside panic(), so no need to unset it
before calling panic() in end_report().

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
---
 mm/kasan/report.c | 10 +---------
 1 file changed, 1 insertion(+), 9 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3ad9624..f141465 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -117,16 +117,8 @@ static void end_report(unsigned long *flags, unsigned long addr)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
-		/*
-		 * This thread may hit another WARN() in the panic path.
-		 * Resetting this prevents additional WARN() from panicking the
-		 * system on this thread.  Other threads are blocked by the
-		 * panic_mutex in panic().
-		 */
-		panic_on_warn = 0;
+	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
 		panic("panic_on_warn set ...\n");
-	}
 	if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
 		panic("kasan.fault=panic set ...\n");
 	kasan_enable_current();
-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1644324666-15947-6-git-send-email-yangtiezhu%40loongson.cn.
