Return-Path: <kasan-dev+bncBAABBROUY3EQMGQE5QOCWSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EF7DCA4470
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 16:35:42 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-47921784b97sf7106615e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 07:35:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764862537; cv=pass;
        d=google.com; s=arc-20240605;
        b=kDML4JQ87pt5zEmxKcJc11KSCIKetk1odSNecxJyW0k7MWqDNuXWM56jNLIMfvjWwC
         ujJzvqQAN56631UCK1VZjZXvJ4xG+eveT9kTKFhsJLkW0HCeKcpBfoBOxXUnEoSku9Pf
         +PLZJ2hMxrSNbrDRZnuuOYiw11F7iYOZiRLwrmFKnIspcBF1xTsY69f7BGh70n6k/GUT
         MbOUO9HPpjcXiT4G8zPQhD+ouL5EqpVEi/hkoCvTQkonlQTxINoVeTinhzd/Myf0K7pZ
         /IA725v7tpyzkEMMiheQzk4cMXldPq9g0oI08iG+kmifPlhdkQXXg2odhSnUu8waBAeZ
         FVMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:cc:to
         :subject:tls-required:message-id:from:date:mime-version:sender
         :dkim-signature;
        bh=UAIbWae1qlSldi2b5uauG7TjNyYPvKRbOWd/qw3R7+c=;
        fh=tvmRQezgpwsXGTj4Q/X/Xw6OkEy7/h6kf7JGzKGM1Qc=;
        b=e0lZxHne4PsbZNrjAcuD2Gtn2Kz0BQjmozuXguwAraevkOB4l8lH/oEN91pVDAphyX
         qdDbim60tdWIF/7LKHXdtAwQEfzPn5maz9IIw5jIRDB9E9t6001w2aHPa8kDsXnLjCcf
         AzemL01UyWd2zKfgntjsOFmWr7YbIPOtsI+pDh6pmBg4USkTQgO91UJ+K94A9gbAEE35
         nieP/WqRxti4miNm24IwaNkriX43seS/FgvkZacqwHlXKybSheOtTRfvIh10AUXc65Ll
         LUAvFqv0nPgw06AsNeRwT7SYyXLbt0ws2Myq4tsF53FwjPbbhCWePV1ySVFIVUHud/Ra
         cFEw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bG4Wr0P6;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764862537; x=1765467337; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:cc:to:subject:tls-required
         :message-id:from:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UAIbWae1qlSldi2b5uauG7TjNyYPvKRbOWd/qw3R7+c=;
        b=XEogEBKsb8T5OLRxig7uOleGPIwYcZxIaOhNgFIkz+7Pw+8ucK4RtLlS2RIWD3v5uu
         +TT4Kp0uMpfpOT1Ge5V+8BCuXZjd7tHlg9m9+jvrsmgHDOs8GRMj99ubU1CDeZUVxxav
         Jb0NAZW77S/8+YmFKIt+FVlZPaBQck3rMOqfzHsNiRf+W3e7k8Q4ImxWUBDDFtMw+xG+
         y1uEz1NyZMmHMvFyyygac6Mx65wLy68Sw7hnemS6nZmNgdizjO5tPiEF6ErPbrMV82TD
         jj+J2tP+P8wGnVmO3MgBeF4Ju8bKIHTRrQFke2hxemh14xePX+sJJYs2hg1BgeNpnJ1Q
         EwHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764862537; x=1765467337;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:cc:to:subject:tls-required:message-id:from:date
         :mime-version:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UAIbWae1qlSldi2b5uauG7TjNyYPvKRbOWd/qw3R7+c=;
        b=UivelIE3Bmlby45BhHWpAx8Bbfi3oZfSpjD9XD8negX5cKbOFPLYvQzYTRvsvOhLqt
         DESQuCk7ci5hnWEZR5KWDrPMGXbi6byw+yOV0U6QdYla31t/fm94wBwpPBJXqt4bDiqK
         Xsco9IS3AtPDLeAf1Ty5mkmrIWDhShjyXEARlAc3W1QDpgZaQouKGm3aYSCyuXxbC+lo
         02EJch7WtKsmitwTGvnufTItuQoLmweOUm44yOwaS9aDItBsBq3JTVIhMEMFTWlpsB3B
         dBItaCduW3JuYsgTz5DTZZBn1yVmR0v9wUcNc9q0LTmnQGVc+pGF6zga59wckeqTdtLn
         B6jA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXy3eKI7+mnuHHRtbPkVgErG4bJ9rYFAIoSoUdeLo7rCFRkaFHK+Qar1/vFiCvYNqCYY281Zw==@lfdr.de
X-Gm-Message-State: AOJu0Yw4a3dNSo08a7O5fVHYjMeXFpZZ83XQiXpyMsLx2Mzf8x+orOm+
	9Orxy/l7SfnJscek1RFoQS2noCuhAE2iecu+MP9seKoC/XjUupHVi+xR
X-Google-Smtp-Source: AGHT+IEfLgeo1A//BruBfYj5mQdmEg4sTByOGqeZR+kZDfanq4916ZSJSHIryLgKyAUBfmemLX89dA==
X-Received: by 2002:a05:600c:458d:b0:477:7af8:c8ad with SMTP id 5b1f17b1804b1-4792af413e3mr77559095e9.31.1764862534272;
        Thu, 04 Dec 2025 07:35:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bDbAqMDcT0gNCUDgMO3s8FF2vOp7FqLOtj4QAS2QAkow=="
Received: by 2002:a05:600c:3e18:b0:471:e4b:ff10 with SMTP id
 5b1f17b1804b1-47930bda9cels4593225e9.2.-pod-prod-06-eu; Thu, 04 Dec 2025
 07:35:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXkrcRdrLuxl6hRW+JTF7V7/RBS9bmEV9LWJvhaLeuSm0s1lIfasB0kGMMU4GbGACmHnFnpAEFuTB0=@googlegroups.com
X-Received: by 2002:a05:600c:45d2:b0:477:9b35:3e49 with SMTP id 5b1f17b1804b1-4792aed9cdemr68630165e9.3.1764862532039;
        Thu, 04 Dec 2025 07:35:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764862531; cv=none;
        d=google.com; s=arc-20240605;
        b=SEsPZnC7sWSyZtXCohPF0J9Cki6FGl9dQucLi1H9qMRcNjkc0rGGuS8G1vIv8C/lnI
         6OSEF7L7tv26VmpsA5ltR1DYDghRkyJzY+JRvuF2msXZgoUgkjtPN8uqu1lvq+7YYEJ9
         gyNMSdMp7yXmsXFpt+Dp/nqQSToBV8jYsNla8ppDX4qjWPD1G++J/3LNOsSPrggoXSXe
         a8ny5JmtXzr/DBMDcGIZPv50R3BrlNJvHPQbi5+75HErxGV8zWnlXEXl36GFavzdznkV
         /F6vyOvJHaR6uIivqkGLhmsG27sZcTXYonx97/BMAG1Xb19RoJHBWk/RuOK9GSSaL7iK
         Em7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:in-reply-to:cc:to:subject:tls-required:message-id:from
         :content-transfer-encoding:date:dkim-signature:mime-version;
        bh=cSWBjoUbSEGuP/Fanmcv3C5LwDckSbaugls2GY15bOc=;
        fh=Gv3L7xMmNXrRxIzhJdjTkte8DfnRggskTjhwZk/9Mnc=;
        b=kviiHkBN/iOhH6uuyZXDp/iO0W3kVtbgPNbd+XXaOLUOGYcp9hd5dLylirob0JfuEo
         QdUFpKEQh/UeZi90iBljieGRo20PjgviBA8g1RflLG1afskuJcwjlopfmw58zQMaOVe6
         lFDi1c3ZI9fHt5KtA0VSQjVJ0ZmzJVsCCRm1ma3I2/8PHehmeiYr8LWlARecyQKbcSYp
         dKIz1s2rQ7eIvm/8Bjw8Fkoru1lzDX2lnFQeZWps7waSUfNy9kcak9KWrr5apqyAM6cG
         NwB9MvLlPTjoCZNSDZH4N83qNuqRGayTtjVXuzMXhjiNW6+ewrYccir/zGoOUkAvmNZf
         PNtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bG4Wr0P6;
       spf=pass (google.com: domain of jiayuan.chen@linux.dev designates 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta1.migadu.com (out-189.mta1.migadu.com. [2001:41d0:203:375::bd])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4792b12463asi389225e9.2.2025.12.04.07.35.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 07:35:31 -0800 (PST)
Received-SPF: pass (google.com: domain of jiayuan.chen@linux.dev designates 2001:41d0:203:375::bd as permitted sender) client-ip=2001:41d0:203:375::bd;
MIME-Version: 1.0
Date: Thu, 04 Dec 2025 15:35:23 +0000
Content-Type: text/plain; charset="UTF-8"
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: "Jiayuan Chen" <jiayuan.chen@linux.dev>
Message-ID: <5dce1baa4672646c54beaa94355e32fab856fa2b@linux.dev>
TLS-Required: No
Subject: Re: [PATCH v1] mm/kasan: Fix incorrect unpoisoning in vrealloc for
 KASAN
To: "Andrey Konovalov" <andreyknvl@gmail.com>
Cc: "Maciej Wieczor-Retman" <m.wieczorretman@pm.me>, "Maciej Wieczor-Retman"
 <maciej.wieczor-retman@intel.com>, linux-mm@kvack.org,
 syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com, "Andrey Ryabinin"
 <ryabinin.a.a@gmail.com>, "Alexander Potapenko" <glider@google.com>,
 "Dmitry Vyukov" <dvyukov@google.com>, "Vincenzo Frascino"
 <vincenzo.frascino@arm.com>, "Andrew Morton" <akpm@linux-foundation.org>,
 "Uladzislau Rezki" <urezki@gmail.com>, "Danilo Krummrich"
 <dakr@kernel.org>, "Kees Cook" <kees@kernel.org>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
In-Reply-To: <CA+fCnZfn+bu15DPwawApE3DXrEz_wkYzHdjbjbTD0n5KLEQfsQ@mail.gmail.com>
References: <5o7owlr4ap5fridqlkerrnuvwwlgldr35gvkcf6df4fufatrr6@yn5rmfn54i62>
 <ef40d7bb8d28a5cde0547945a0a44e05b56d0e76@linux.dev>
 <CA+fCnZfn+bu15DPwawApE3DXrEz_wkYzHdjbjbTD0n5KLEQfsQ@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: jiayuan.chen@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bG4Wr0P6;       spf=pass
 (google.com: domain of jiayuan.chen@linux.dev designates 2001:41d0:203:375::bd
 as permitted sender) smtp.mailfrom=jiayuan.chen@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

December 4, 2025 at 23:06, "Andrey Konovalov" <andreyknvl@gmail.com mailto:andreyknvl@gmail.com?to=%22Andrey%20Konovalov%22%20%3Candreyknvl%40gmail.com%3E > wrote:


> 
> On Thu, Dec 4, 2025 at 3:38 PM Jiayuan Chen <jiayuan.chen@linux.dev> wrote:
> 
> > 
> > I think I don't need KEEP_TAG flag anymore, following patch works well and all kasan tests run successfully
> >  with CONFIG_KASAN_SW_TAGS/CONFIG_KASAN_HW_TAGS/CONFIG_KASAN_GENERIC
> > 
> Thanks for working on improving the vrealloc annotations!
> 
> But I think we need to first fix the vrealloc issue you discovered in
> a separate patch (so that it can be backported), and then we can apply
> your other vrealloc changes on top later.
> 
> So please implement a version of your fix with KEEP_TAG -- this would
> also allow Maciej to build on top.

Thanks, i will just use KEEP_TAG and make the patch as simple as possible.

CC Maciej

Thanks.

> > 
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> >  index 1c373cc4b3fa..8b819a9b2a27 100644
> >  --- a/mm/kasan/hw_tags.c
> >  +++ b/mm/kasan/hw_tags.c
> >  @@ -394,6 +394,11 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
> >  * The physical pages backing the vmalloc() allocation are poisoned
> >  * through the usual page_alloc paths.
> >  */
> >  + if (!is_vmalloc_or_module_addr(start))
> >  + return;
> >  +
> >  + size = round_up(size, KASAN_GRANULE_SIZE);
> >  + kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
> > 
> This does not look good - we will end up poisoning the same memory
> twice, once here and once it's freed to page_alloc.
> 
> Is this change required?
> 
> > 
> > }
> > 
> >  #endif
> >  diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> >  index 2cafca31b092..a5f683c3abde 100644
> >  --- a/mm/kasan/kasan_test_c.c
> >  +++ b/mm/kasan/kasan_test_c.c
> >  @@ -1840,6 +1840,84 @@ static void vmalloc_helpers_tags(struct kunit *test)
> >  vfree(ptr);
> >  }
> > 
> >  +
> >  +static void vrealloc_helpers(struct kunit *test, bool tags)
> >  +{
> >  + char *ptr;
> >  + size_t size = PAGE_SIZE / 2 - KASAN_GRANULE_SIZE - 5;
> >  +
> >  + if (!kasan_vmalloc_enabled())
> >  + kunit_skip(test, "Test requires kasan.vmalloc=on");
> >  +
> >  + ptr = (char *)vmalloc(size);
> >  + KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >  +
> >  + OPTIMIZER_HIDE_VAR(ptr);
> >  +
> >  + size += PAGE_SIZE / 2;
> >  + ptr = vrealloc(ptr, size, GFP_KERNEL);
> >  + /* Check that the returned pointer is tagged. */
> >  + if (tags) {
> >  + KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
> >  + KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> >  + }
> >  + /* Make sure in-bounds accesses are valid. */
> >  + ptr[0] = 0;
> >  + ptr[size - 1] = 0;
> >  +
> >  + /* Make sure exported vmalloc helpers handle tagged pointers. */
> >  + KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
> >  + KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
> >  +
> >  + size -= PAGE_SIZE / 2;
> >  + ptr = vrealloc(ptr, size, GFP_KERNEL);
> >  +
> >  + /* Check that the returned pointer is tagged. */
> >  + KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
> >  + KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> >  +
> >  + /* Make sure exported vmalloc helpers handle tagged pointers. */
> >  + KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
> >  + KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
> >  +
> >  +
> >  + /* This access must cause a KASAN report. */
> >  + KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)ptr)[size + 5]);
> >  +
> >  +
> >  +#if !IS_MODULE(CONFIG_KASAN_KUNIT_TEST)
> >  + {
> >  + int rv;
> >  +
> >  + /* Make sure vrealloc'ed memory permissions can be changed. */
> >  + rv = set_memory_ro((unsigned long)ptr, 1);
> >  + KUNIT_ASSERT_GE(test, rv, 0);
> >  + rv = set_memory_rw((unsigned long)ptr, 1);
> >  + KUNIT_ASSERT_GE(test, rv, 0);
> >  + }
> >  +#endif
> >  +
> >  + vfree(ptr);
> >  +}
> >  +
> >  +static void vrealloc_helpers_tags(struct kunit *test)
> >  +{
> >  + /* This test is intended for tag-based modes. */
> >  + KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
> >  +
> >  + KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
> >  + vrealloc_helpers(test, true);
> >  +}
> >  +
> >  +static void vrealloc_helpers_generic(struct kunit *test)
> >  +{
> >  + /* This test is intended for tag-based modes. */
> >  + KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
> >  +
> >  + KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
> >  + vrealloc_helpers(test, false);
> >  +}
> >  +
> >  static void vmalloc_oob(struct kunit *test)
> >  {
> >  char *v_ptr, *p_ptr;
> >  @@ -2241,6 +2319,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
> >  KUNIT_CASE_SLOW(kasan_atomics),
> >  KUNIT_CASE(vmalloc_helpers_tags),
> >  KUNIT_CASE(vmalloc_oob),
> >  + KUNIT_CASE(vrealloc_helpers_tags),
> >  + KUNIT_CASE(vrealloc_helpers_generic),
> >  KUNIT_CASE(vmap_tags),
> >  KUNIT_CASE(vm_map_ram_tags),
> >  KUNIT_CASE(match_all_not_assigned),
> >  diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> >  index 798b2ed21e46..9ba2e8a346d6 100644
> >  --- a/mm/vmalloc.c
> >  +++ b/mm/vmalloc.c
> >  @@ -4128,6 +4128,7 @@ EXPORT_SYMBOL(vzalloc_node_noprof);
> >  void *vrealloc_node_align_noprof(const void *p, size_t size, unsigned long align,
> >  gfp_t flags, int nid)
> >  {
> >  + asan_vmalloc_flags_t flags;
> >  struct vm_struct *vm = NULL;
> >  size_t alloced_size = 0;
> >  size_t old_size = 0;
> >  @@ -4158,25 +4159,26 @@ void *vrealloc_node_align_noprof(const void *p, size_t size, unsigned long align
> >  goto need_realloc;
> >  }
> > 
> >  + flags = KASAN_VMALLOC_PROT_NORMAL | KASAN_VMALLOC_VM_ALLOC;
> >  /*
> >  * TODO: Shrink the vm_area, i.e. unmap and free unused pages. What
> >  * would be a good heuristic for when to shrink the vm_area?
> >  */
> >  - if (size <= old_size) {
> >  + if (p && size <= old_size) {
> >  /* Zero out "freed" memory, potentially for future realloc. */
> >  if (want_init_on_free() || want_init_on_alloc(flags))
> >  memset((void *)p + size, 0, old_size - size);
> >  vm->requested_size = size;
> >  - kasan_poison_vmalloc(p + size, old_size - size);
> >  + kasan_poison_vmalloc(p, alloced_size);
> >  + p = kasan_unpoison_vmalloc(p, size, flags);
> >  return (void *)p;
> >  }
> > 
> >  /*
> >  * We already have the bytes available in the allocation; use them.
> >  */
> >  - if (size <= alloced_size) {
> >  - kasan_unpoison_vmalloc(p + old_size, size - old_size,
> >  - KASAN_VMALLOC_PROT_NORMAL);
> >  + if (p && size <= alloced_size) {
> >  + p = kasan_unpoison_vmalloc(p, size, flags);
> >  /*
> >  * No need to zero memory here, as unused memory will have
> >  * already been zeroed at initial allocation time or during
> >
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5dce1baa4672646c54beaa94355e32fab856fa2b%40linux.dev.
